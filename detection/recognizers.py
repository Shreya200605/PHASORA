
import re


class IndianPIIRecognizers:

    PATTERNS = {
        "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "GSTIN": r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b",
        "AADHAAR": r"\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",
        "PASSPORT": r"\b[A-PR-WYa-pr-wy][0-9]{7}\b",
        "VOTER_ID": r"\b[A-Z]{3}[0-9]{7}\b"
    }

    def detect(self, text):

        findings = []

        for entity_type, pattern in self.PATTERNS.items():

            matches = re.finditer(pattern, text)

            for match in matches:

                value = match.group()

                if entity_type == "PAN":
                    if not self.validate_pan(value):
                        continue

                if entity_type == "AADHAAR":
                    if not self.validate_aadhaar(value):
                        continue

                findings.append({
                    "entity_type": entity_type,
                    "start": match.start(),
                    "end": match.end(),
                    "score": 1.0,
                    "value": value
                })

        return findings

    @staticmethod
    def validate_pan(value):

        return bool(
            re.fullmatch(
                r"[A-Z]{5}[0-9]{4}[A-Z]",
                value
            )
        )

    @staticmethod
    def validate_aadhaar(value):

        digits = re.sub(r"\s", "", value)

        if not re.fullmatch(r"[2-9][0-9]{11}", digits):
            return False

        return IndianPIIRecognizers.verhoeff_check(digits)

    @staticmethod
    def verhoeff_check(number):

        multiplication = [
            [0,1,2,3,4,5,6,7,8,9],
            [1,2,3,4,0,6,7,8,9,5],
            [2,3,4,0,1,7,8,9,5,6],
            [3,4,0,1,2,8,9,5,6,7],
            [4,0,1,2,3,9,5,6,7,8],
            [5,9,8,7,6,0,4,3,2,1],
            [6,5,9,8,7,1,0,4,3,2],
            [7,6,5,9,8,2,1,0,4,3],
            [8,7,6,5,9,3,2,1,0,4],
            [9,8,7,6,5,4,3,2,1,0]
        ]

        permutation = [
            [0,1,2,3,4,5,6,7,8,9],
            [1,5,7,6,2,8,3,0,9,4],
            [5,8,0,3,7,9,6,1,4,2],
            [8,9,1,6,0,4,3,5,2,7],
            [9,4,5,3,1,2,6,8,7,0],
            [4,2,8,6,5,7,3,9,0,1],
            [2,7,9,3,8,0,6,4,1,5],
            [7,0,4,6,9,1,3,2,5,8]
        ]

        check = 0
        reversed_digits = [int(digit) for digit in reversed(number)]

        for index, digit in enumerate(reversed_digits):
            check = multiplication[
                check
            ][
                permutation[index % 8][digit]
            ]

        return check == 0
