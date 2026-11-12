
import re

from security.tripwire import PrivacyTripwire
from security.attack_detector import PlaceholderAttackDetector
from security.integrity import PlaceholderIntegrity


class PrivacyController:

    def __init__(self):
        self.tripwire = PrivacyTripwire()
        self.attack_detector = PlaceholderAttackDetector()
        self.integrity = PlaceholderIntegrity()

    @staticmethod
    def _find_exact_leaks(sanitized_text, detected_entities, decisions):

        findings = []

        for entity, decision in zip(detected_entities, decisions):

            if decision.get("action") == "RETAIN":
                continue

            value = str(entity.get("value", "")).strip()

            if not value:
                continue

            normalized_value = " ".join(value.casefold().split())
            normalized_text = " ".join(
                sanitized_text.casefold().split()
            )

            if normalized_value.isdigit():
                pattern = (
                    r"(?<!\d)"
                    + re.escape(normalized_value)
                    + r"(?!\d)"
                )

                leaked = re.search(pattern, normalized_text) is not None

            else:
                leaked = normalized_value in normalized_text

            if leaked:
                findings.append({
                    "entity_type": entity.get(
                        "entity_type",
                        "UNKNOWN"
                    ),
                    "reason": "Original detected value remains outbound."
                })

        return findings

    def validate_outbound(
        self,
        sanitized_text,
        detected_entities=None,
        decisions=None
    ):

        result = self.tripwire.inspect(sanitized_text)

        if not result["safe"]:
            return {
                "approved": False,
                "reason": (
                    "Sensitive information detected "
                    "in outbound payload."
                ),
                "leakage_count": result.get("leakage_count", 0),
                "exact_value_findings": []
            }

        detected_entities = detected_entities or []
        decisions = decisions or []

        exact_leaks = self._find_exact_leaks(
            sanitized_text,
            detected_entities,
            decisions
        )

        if exact_leaks:
            return {
                "approved": False,
                "reason": (
                    "Original detected values remain "
                    "in outbound payload."
                ),
                "leakage_count": len(exact_leaks),
                "exact_value_findings": exact_leaks
            }

        return {
            "approved": True,
            "reason": "Outbound payload passed privacy inspection.",
            "leakage_count": 0,
            "exact_value_findings": []
        }

    def validate_response(self, response, valid_placeholders):

        attack_result = self.attack_detector.inspect(
            response,
            valid_placeholders
        )

        integrity_result = self.integrity.inspect(
            response,
            valid_placeholders
        )

        approved = (
            attack_result["safe"]
            and integrity_result["safe"]
        )

        return {
            "approved": approved,
            "attack_result": attack_result,
            "integrity_result": integrity_result
        }
