
import re
import json
import hashlib
import hmac


class PlaceholderIntegrity:

    PATTERN = re.compile(r"<[A-Z][A-Z0-9_]*_\d+>")

    def create_signature(self, placeholders, secret):

        ordered = sorted(set(placeholders))
        payload = "|".join(ordered).encode("utf-8")

        return hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256
        ).hexdigest()

    def verify_signature(self, placeholders, signature, secret):

        expected = self.create_signature(
            placeholders,
            secret
        )

        return hmac.compare_digest(expected, signature)

    def sign_mapping(self, mapping, secret):

        payload = json.dumps(
            sorted(mapping.items()),
            ensure_ascii=False,
            separators=(",", ":")
        ).encode("utf-8")

        return hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256
        ).hexdigest()

    def verify_mapping(self, mapping, signature, secret):

        expected = self.sign_mapping(mapping, secret)

        return hmac.compare_digest(expected, signature)

    def inspect(self, text, valid_placeholders):

        found = set(self.PATTERN.findall(text))
        valid = set(valid_placeholders)

        unknown = sorted(found - valid)
        missing = sorted(valid - found)

        return {
            "safe": len(unknown) == 0,
            "unknown": unknown,
            "missing": missing,
            "found_count": len(found)
        }
