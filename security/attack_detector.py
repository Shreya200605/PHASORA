
import re


class PlaceholderAttackDetector:

    PLACEHOLDER_PATTERN = re.compile(
        r"<([A-Z][A-Z0-9_]*_\d+)>"
    )

    def inspect(self, text, valid_placeholders):

        found = [
            match.group(0)
            for match in self.PLACEHOLDER_PATTERN.finditer(text)
        ]

        valid = set(valid_placeholders)

        unknown = sorted(set(found) - valid)

        return {
            "safe": len(unknown) == 0,
            "unknown_placeholders": unknown,
            "total_placeholders": len(found)
        }

    def enforce(self, text, valid_placeholders):

        result = self.inspect(text, valid_placeholders)

        if not result["safe"]:
            raise ValueError(
                "Unknown or manipulated placeholder detected."
            )

        return True
