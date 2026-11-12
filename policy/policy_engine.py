class PolicyEngine:

    ACTIONS = {
        "MASK",
        "RETAIN",
        "GENERALIZE",
        "TRANSFORM",
        "BLOCK"
    }

    def __init__(self):
        self.default_policy = {
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
            "INCOME": "TRANSFORM"
        }

    def get_action(self, entity_type, purpose="general"):

        entity_type = entity_type.upper()

        if entity_type in self.default_policy:
            action = self.default_policy[entity_type]
        else:
            action = "MASK"

        if action not in self.ACTIONS:
            return "BLOCK"

        return action

    def evaluate(self, detected_entities, purpose="general"):

        decisions = []

        for entity in detected_entities:

            entity_type = entity.get("entity_type", "UNKNOWN")

            action = self.get_action(
                entity_type,
                purpose
            )

            decisions.append({
                "entity_type": entity_type,
                "value": entity.get("value", ""),
                "action": action
            })

        return decisions