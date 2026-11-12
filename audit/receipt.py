from datetime import datetime, timezone


class PrivacyReleaseReceipt:

    def generate(
        self,
        request_id,
        decisions,
        security_result,
        model_name="External LLM"
    ):

        entity_summary = {}

        for decision in decisions:

            entity_type = decision["entity_type"]
            action = decision["action"]

            if entity_type not in entity_summary:
                entity_summary[entity_type] = {
                    "detected": 0,
                    "actions": {}
                }

            entity_summary[entity_type]["detected"] += 1

            entity_summary[entity_type]["actions"][action] = (
                entity_summary[entity_type]["actions"].get(action, 0) + 1
            )

        return {
            "receipt_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model": model_name,
            "entities": entity_summary,
            "outbound_security_check": (
                "PASSED" if security_result["approved"] else "BLOCKED"
            ),
            "privacy_mapping_stored": False,
            "original_pii_stored": False
        }