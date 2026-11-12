
import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider


class PIIDetector:

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

    def detect(self, text):
        results = self.analyzer.analyze(
            text=text,
            language="en"
        )

        detected_entities = []

        for result in results:
            detected_entities.append({
                "entity_type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "score": round(result.score, 2),
                "value": text[result.start:result.end]
            })

        return detected_entities
