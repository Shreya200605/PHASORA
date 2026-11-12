import re


class PlaceholderReinserter:

    PATTERN = re.compile(r"<([A-Z][A-Z0-9_]*_\d+)>")

    def restore(self, response, mapping):

        found = {
            match.group(0)
            for match in self.PATTERN.finditer(response)
        }

        valid = set(mapping.keys())

        unknown = found - valid

        if unknown:
            raise ValueError(
                "Unknown placeholder detected. Restoration blocked."
            )

        restored_response = response

        for placeholder, original_value in mapping.items():

            restored_response = restored_response.replace(
                placeholder,
                original_value
            )

        return restored_response