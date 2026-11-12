
import re

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

    FINANCIAL_PATTERNS = {

        "INCOME": re.compile(
            r"\b(?:monthly\s+)?(?:income|salary|earnings)"
            r"\b.{0,20}?(?:₹|Rs\.?|INR)?\s*"
            r"(\d+(?:,\d{2,3})*(?:\.\d{1,2})?)",
            re.IGNORECASE
        ),

        "EMI": re.compile(
            r"\b(?:monthly\s+)?(?:EMI|instalment|installment)"
            r"\b.{0,20}?(?:₹|Rs\.?|INR)?\s*"
            r"(\d+(?:,\d{2,3})*(?:\.\d{1,2})?)",
            re.IGNORECASE
        ),

        "AGE": re.compile(
            r"\bage\s*(?:is|of|:|=)?\s*"
            r"(\d{1,3})"
            r"(?:\s*(?:years?\s*old|years?|yrs?))?",
            re.IGNORECASE
        )
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

        financial_candidates = []

        for entity_type, pattern in self.FINANCIAL_PATTERNS.items():

            for match in pattern.finditer(text):

                number_start, number_end = match.span(1)

                start = number_start
                end = number_end

                if entity_type in {"INCOME", "EMI"}:

                    prefix = text[match.start():number_start]

                    currency_match = re.search(
                        r"\?*\s*(?:₹|Rs\.?|INR)\s*$",
                        prefix,
                        re.IGNORECASE
                    )

                    if currency_match:
                        start = match.start() + currency_match.start()

                elif entity_type == "AGE":
                    end = match.end()

                financial_candidates.append({
                    "entity_type": entity_type,
                    "start": start,
                    "end": end,
                    "score": 1.0,
                    "value": match.group(1).replace(",", "")
                })

        results = self.analyzer.analyze(
            text=text,
            language="en"
        )

        candidates = list(indian_entities)
        candidates.extend(financial_candidates)

        for result in results:

            if result.entity_type not in self.ALLOWED_ENTITIES:
                continue

            value = text[result.start:result.end]

            if result.entity_type == "DATE_TIME":

                if value.strip().lower() in {
                    "monthly",
                    "daily",
                    "weekly",
                    "yearly",
                    "annually"
                }:
                    continue

            if (
                result.entity_type == "PERSON"
                and value.strip().upper() in self.LABEL_WORDS
            ):
                continue

            overlaps_indian = any(
                result.start < entity["end"]
                and result.end > entity["start"]
                for entity in indian_entities
            )

            overlaps_financial = any(
                result.start < entity["end"]
                and result.end > entity["start"]
                for entity in financial_candidates
            )

            if overlaps_indian or overlaps_financial:
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
