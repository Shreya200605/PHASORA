from security.tripwire import PrivacyTripwire
from security.attack_detector import PlaceholderAttackDetector
from security.integrity import PlaceholderIntegrity


class PrivacyController:

    def __init__(self):
        self.tripwire = PrivacyTripwire()
        self.attack_detector = PlaceholderAttackDetector()
        self.integrity = PlaceholderIntegrity()

    def validate_outbound(self, sanitized_text):

        result = self.tripwire.inspect(sanitized_text)

        if not result["safe"]:
            return {
                "approved": False,
                "reason": "Sensitive information detected in outbound payload."
            }

        return {
            "approved": True,
            "reason": "Outbound payload passed privacy inspection."
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