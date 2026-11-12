
class PolicyEngine:

    ACTIONS = {
        "MASK",
        "RETAIN",
        "GENERALIZE",
        "TRANSFORM",
        "BLOCK"
    }

    DEFAULT_POLICY = {
        "PERSON": "MASK",
        "PHONE_NUMBER": "MASK",
        "EMAIL_ADDRESS": "MASK",
        "AADHAAR": "MASK",
        "PAN": "MASK",
        "GSTIN": "MASK",
        "PASSPORT": "MASK",
        "VOTER_ID": "MASK",
        "ADDRESS": "GENERALIZE",
        "AGE": "GENERALIZE",
        "INCOME": "TRANSFORM",
        "EMI": "MASK"
    }

    PURPOSE_POLICIES = {

        "loan": {
            "PERSON": "MASK",
            "PAN": "MASK",
            "AADHAAR": "MASK",
            "INCOME": "TRANSFORM",
            "EMI": "TRANSFORM",
            "AGE": "GENERALIZE",
            "ADDRESS": "GENERALIZE"
        },

        "kyc": {
            "PERSON": "MASK",
            "PAN": "MASK",
            "AADHAAR": "MASK",
            "GSTIN": "MASK",
            "PASSPORT": "MASK",
            "VOTER_ID": "MASK",
            "ADDRESS": "GENERALIZE",
            "INCOME": "MASK",
            "EMI": "MASK"
        },

        "customer_support": {
            "PERSON": "MASK",
            "PHONE_NUMBER": "MASK",
            "EMAIL_ADDRESS": "MASK",
            "ADDRESS": "GENERALIZE",
            "PAN": "MASK",
            "AADHAAR": "MASK",
            "INCOME": "MASK",
            "EMI": "MASK"
        },

        "insurance": {
            "PERSON": "MASK",
            "PAN": "MASK",
            "AADHAAR": "MASK",
            "AGE": "GENERALIZE",
            "INCOME": "TRANSFORM",
            "EMI": "TRANSFORM",
            "ADDRESS": "GENERALIZE"
        }
    }

    def get_action(self, entity_type, purpose="general"):

        entity_type = entity_type.upper()
        purpose = purpose.lower().strip()

        purpose_policy = self.PURPOSE_POLICIES.get(
            purpose,
            {}
        )

        action = purpose_policy.get(
            entity_type,
            self.DEFAULT_POLICY.get(entity_type, "MASK")
        )

        if action not in self.ACTIONS:
            return "BLOCK"

        return action

    def evaluate(self, detected_entities, purpose="general"):

        decisions = []

        for entity in detected_entities:

            entity_type = entity.get(
                "entity_type",
                "UNKNOWN"
            )

            action = self.get_action(
                entity_type,
                purpose
            )

            decisions.append({
                "entity_type": entity_type,
                "value": entity.get("value", ""),
                "action": action,
                "purpose": purpose
            })

        return decisions
