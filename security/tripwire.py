
import re


class PrivacyTripwire:

    PATTERNS = {
        "AADHAAR": r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
        "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "GSTIN": r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b",
        "PASSPORT": r"\b[A-PR-WY][0-9]{7}\b",
        "VOTER_ID": r"\b[A-Z]{3}[0-9]{7}\b",
        "EMAIL_ADDRESS": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "PHONE_NUMBER": r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)",
        "CREDIT_CARD": r"\b(?:\d[ -]?){13,19}\b"
    }

    def inspect(self, text):

        findings = []

        for entity_type, pattern in self.PATTERNS.items():

            for match in re.finditer(pattern, text):

                value = match.group()

                if entity_type == "CREDIT_CARD":
                    digits = re.sub(r"\D", "", value)

                    if not 13 <= len(digits) <= 19:
                        continue

                findings.append({
                    "entity_type": entity_type,
                    "start": match.start(),
                    "end": match.end()
                })

        return {
            "safe": len(findings) == 0,
            "leakage_count": len(findings),
            "findings": findings
        }

    def enforce(self, text):

        result = self.inspect(text)

        if not result["safe"]:
            raise ValueError(
                "Privacy Tripwire blocked the outgoing payload."
            )

        return True
