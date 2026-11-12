
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from detection.recognizers import IndianPIIRecognizers


class PIIDetector:

    ALLOWED_ENTITIES = {
        "PERSON",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "LOCATION",
        "DATE_TIME",
        "CREDIT_CARD",
        "IP_ADDRESS",
        "IBAN_CODE"
    }

    LABEL_WORDS = {
        "EMAIL",
        "PHONE",
        "MOBILE",
        "PAN",
        "GSTIN",
        "AADHAAR",
        "PASSPORT",
        "VOTER",
        "ADDRESS",
        "NAME"
    }

    def __init__(self):

        configuration = {
            "nlp_engine_name": "spacy",
            "models": [
                {
                    "lang_code": "en",
                    "model_name": "en_core_web_sm"
                }
            ]
        }

        provider = NlpEngineProvider(
            nlp_configuration=configuration
        )

        nlp_engine = provider.create_engine()

        self.analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["en"]
        )

        self.indian_recognizer = IndianPIIRecognizers()

    def detect(self, text):

        indian_entities = self.indian_recognizer.detect(text)

        results = self.analyzer.analyze(
            text=text,
            language="en"
        )

        candidates = list(indian_entities)

        for result in results:

            if result.entity_type not in self.ALLOWED_ENTITIES:
                continue

            value = text[result.start:result.end]

            if (
                result.entity_type == "PERSON"
                and value.strip().upper() in self.LABEL_WORDS
            ):
                continue

            overlaps_indian_identifier = any(
                result.start < entity["end"]
                and result.end > entity["start"]
                for entity in indian_entities
            )

            if overlaps_indian_identifier:
                continue

            candidates.append({
                "entity_type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "score": round(result.score, 2),
                "value": value
            })

        candidates.sort(
            key=lambda item: (
                item["start"],
                item["end"]
            )
        )

        detected_entities = []
        last_end = -1

        for entity in candidates:

            if entity["start"] >= last_end:
                detected_entities.append(entity)
                last_end = entity["end"]

        return detected_entities
