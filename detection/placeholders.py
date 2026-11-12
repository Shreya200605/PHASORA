
import re


class PlaceholderManager:

    def __init__(self):
        # Separate counter for each entity type
        self.counters = {}

        # Placeholder -> original value
        self.mapping = {}

        # (Entity type, original value) -> placeholder
        self.value_to_placeholder = {}

    def generate_placeholder(self, entity_type, original_text):

        # Generate a placeholder that does not already exist
        # in the original document or current mapping.
        while True:

            next_count = self.counters.get(entity_type, 0) + 1
            placeholder = f"<{entity_type}_{next_count}>"

            if placeholder not in original_text and placeholder not in self.mapping:
                self.counters[entity_type] = next_count
                return placeholder

            self.counters[entity_type] = next_count

    def mask_text(self, text, detections):

        if not isinstance(text, str):
            raise TypeError("Input text must be a string.")

        replacements = []

        # Validate all detections before changing manager state.
        for item in detections:

            entity_type = item.get("entity_type")
            original_value = item.get("text")
            start = item.get("start")
            end = item.get("end")

            if not isinstance(entity_type, str) or not re.fullmatch(
                r"[A-Z][A-Z0-9_]*", entity_type
            ):
                raise ValueError("Invalid entity type.")

            if not isinstance(start, int) or isinstance(start, bool):
                raise ValueError("Detection start must be an integer.")

            if not isinstance(end, int) or isinstance(end, bool):
                raise ValueError("Detection end must be an integer.")

            if not isinstance(original_value, str):
                raise ValueError("Detection text must be a string.")

            if not (0 <= start < end <= len(text)):
                raise ValueError("Detection positions are out of range.")

            if text[start:end] != original_value:
                raise ValueError(
                    "Detection text does not match its original text span."
                )

            replacements.append({
                "entity_type": entity_type,
                "text": original_value,
                "start": start,
                "end": end
            })

        # Sort by position and reject overlapping detections.
        replacements.sort(key=lambda item: item["start"])

        for index in range(1, len(replacements)):

            previous = replacements[index - 1]
            current = replacements[index]

            if current["start"] < previous["end"]:
                raise ValueError("Overlapping detections are not allowed.")

        # Assign placeholders after validation.
        for item in replacements:

            entity_type = item["entity_type"]
            original_value = item["text"]

            key = (entity_type, original_value)

            if key in self.value_to_placeholder:
                placeholder = self.value_to_placeholder[key]

            else:
                placeholder = self.generate_placeholder(
                    entity_type,
                    text
                )

                self.value_to_placeholder[key] = placeholder
                self.mapping[placeholder] = original_value

            item["placeholder"] = placeholder

        # Replace from right to left to preserve original positions.
        masked_text = text

        for item in reversed(replacements):

            start = item["start"]
            end = item["end"]
            placeholder = item["placeholder"]

            masked_text = (
                masked_text[:start]
                + placeholder
                + masked_text[end:]
            )

        return masked_text

    def restore_text(self, text):

        if not isinstance(text, str):
            raise TypeError("Restoration input must be a string.")

        if not self.mapping:
            return text

        # Replace known placeholders in one pass.
        # This prevents restored values from triggering
        # another placeholder replacement.
        pattern = re.compile(
            "|".join(
                re.escape(placeholder)
                for placeholder in self.mapping
            )
        )

        return pattern.sub(
            lambda match: self.mapping[match.group(0)],
            text
        )


if __name__ == "__main__":

    from detection.detector import IndianPIIDetector

    sample = """
Customer John Smith applied for a loan.
PAN: ABCPE1234F
GSTIN: 29ABCDE1234F1Z5
Voter ID: ABC1234567
Passport: A1234567
"""

    detector = IndianPIIDetector()
    findings = detector.detect(sample)

    manager = PlaceholderManager()

    masked = manager.mask_text(sample, findings)

    print("\nPRIVACYGUARD AI - MASKED OUTPUT\n")
    print(masked)

    print("\nPLACEHOLDER MAPPING\n")
    print(manager.mapping)

    restored = manager.restore_text(masked)

    print("\nRESTORED OUTPUT\n")
    print(restored)
