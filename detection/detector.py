
import re
import spacy

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry

from detection.recognizers import (
    build_indian_recognizers,
    validate_aadhaar
)


class IndianPIIDetector:

    ADDRESS_LABEL_PATTERN = re.compile(
        r"^[ \t]*(?:(?:permanent|current|residential|mailing|my|mera|meri|nanna)"
        r"[ \t]+)?address(?:[ \t]+(?:hai|is))?[ \t]*[:=-][ \t]*(.*)$",
        re.IGNORECASE
    )

    FIELD_LABEL_PATTERN = re.compile(
        r"^[ \t]*[A-Za-z][A-Za-z0-9 _/-]{0,35}[ \t]*[:=]"
    )

    ADDRESS_PHRASE_PATTERN = re.compile(
        r"\b(?:residing at|lives at|staying at)[ \t]*:?[ \t]*",
        re.IGNORECASE
    )

    NAME_PATTERNS = [
        re.compile(
            r"\b(?:mera|meri)\s+naam\s+"
            r"([A-Z][a-z]+(?:\s+(?!hai\b|is\b)[A-Z][a-z]+){0,3})"
            r"(?=\s+(?:hai|is)\b|[.,\n]|$)",
            re.IGNORECASE
        ),
        re.compile(
            r"\b(?:nanna)\s+hesaru\s+"
            r"([A-Z][a-z]+(?:\s+(?!ide\b|endu\b|is\b|hai\b)[A-Z][a-z]+){0,3})"
            r"(?=\s+(?:ide|endu|is|hai)\b|[.,\n]|$)",
            re.IGNORECASE
        ),
        re.compile(
            r"\bmy\s+name\s+is\s+"
            r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})"
            r"(?=[.,\n]|$)",
            re.IGNORECASE
        )
    ]

    NAME_CUE_WORDS = re.compile(
        r"\b(?:mera|meri|nanna|naam|hesaru|hai|my|name|pan|address)\b",
        re.IGNORECASE
    )

    GSTIN_LIKE_FRAGMENT_PATTERN = re.compile(
        r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][A-Z0-9]{1,3}\b"
    )

    IGNORED_GENERIC_ENTITIES = {
        "US_BANK_NUMBER",
        "US_DRIVER_LICENSE"
    }

    def __init__(self):

        self.nlp = spacy.load("en_core_web_lg")

        self.registry = RecognizerRegistry()
        self.registry.load_predefined_recognizers()

        for recognizer in build_indian_recognizers():
            self.registry.add_recognizer(recognizer)

        self.analyzer = AnalyzerEngine(
            registry=self.registry,
            supported_languages=["en"]
        )

    def extract_address(self, text, start):

        while start < len(text) and text[start] in " \t\r\n":
            start += 1

        if start >= len(text):
            return None

        lines = text.splitlines(keepends=True)

        positions = []
        position = 0

        for line in lines:
            positions.append(position)
            position += len(line)

        line_index = None

        for i, line in enumerate(lines):
            line_end = positions[i] + len(line)

            if positions[i] <= start < line_end:
                line_index = i
                break

        if line_index is None:
            return None

        end = positions[line_index] + len(
            lines[line_index].rstrip("\r\n")
        )

        for i in range(line_index + 1, len(lines)):

            current_line = lines[i]

            if not current_line.strip():
                break

            if self.FIELD_LABEL_PATTERN.match(current_line):
                break

            end = positions[i] + len(
                current_line.rstrip("\r\n")
            )

        while end > start and text[end - 1] in " \t\r\n,.":
            end -= 1

        if end <= start:
            return None

        return {
            "entity_type": "ADDRESS",
            "text": text[start:end],
            "start": start,
            "end": end,
            "score": 0.95
        }

    def detect_addresses(self, text):

        addresses = []
        lines = text.splitlines(keepends=True)
        position = 0

        for line in lines:

            match = self.ADDRESS_LABEL_PATTERN.match(
                line.rstrip("\r\n")
            )

            if match:

                address_start = position + match.start(1)

                result = self.extract_address(
                    text,
                    address_start
                )

                if result:
                    addresses.append(result)

            position += len(line)

        for match in self.ADDRESS_PHRASE_PATTERN.finditer(text):

            result = self.extract_address(
                text,
                match.end()
            )

            if result:
                addresses.append(result)

        addresses.sort(
            key=lambda item: (
                item["start"],
                -(item["end"] - item["start"])
            )
        )

        filtered_addresses = []

        for item in addresses:

            overlap = any(
                item["start"] < existing["end"]
                and item["end"] > existing["start"]
                for existing in filtered_addresses
            )

            if not overlap:
                filtered_addresses.append(item)

        return filtered_addresses

    def detect_explicit_names(self, text):

        names = []

        for pattern in self.NAME_PATTERNS:

            for match in pattern.finditer(text):

                start, end = match.span(1)

                names.append({
                    "entity_type": "PERSON",
                    "text": text[start:end],
                    "start": start,
                    "end": end,
                    "score": 0.90
                })

        return names

    def detect(self, text):

        detections = []

        # 1. Address detection
        address_detections = self.detect_addresses(text)

        address_spans = [
            (item["start"], item["end"])
            for item in address_detections
        ]

        # 2. Explicit name detection
        explicit_names = self.detect_explicit_names(text)

        explicit_name_spans = [
            (item["start"], item["end"])
            for item in explicit_names
        ]

        detections.extend(explicit_names)

        # 3. Presidio detection
        results = self.analyzer.analyze(
            text=text,
            language="en"
        )

        for result in results:

            detected_text = text[result.start:result.end]

            if result.entity_type in self.IGNORED_GENERIC_ENTITIES:
                continue

            inside_address = any(
                result.start >= start and result.end <= end
                for start, end in address_spans
            )

            if inside_address:
                continue

            if result.entity_type == "LOCATION":

                if self.GSTIN_LIKE_FRAGMENT_PATTERN.search(detected_text):
                    continue

            if result.entity_type == "PERSON":

                if self.NAME_CUE_WORDS.search(detected_text):
                    continue

                overlaps_explicit_name = any(
                    result.start < end and result.end > start
                    for start, end in explicit_name_spans
                )

                if overlaps_explicit_name:
                    continue

            if result.entity_type == "AADHAAR":

                if not validate_aadhaar(detected_text):
                    continue

            detections.append({
                "entity_type": result.entity_type,
                "text": detected_text,
                "start": result.start,
                "end": result.end,
                "score": round(result.score, 2)
            })

        # 4. spaCy person detection
        doc = self.nlp(text)

        for entity in doc.ents:

            if entity.label_ != "PERSON":
                continue

            if entity.text.isupper():
                continue

            if self.NAME_CUE_WORDS.search(entity.text):
                continue

            start = entity.start_char
            end = entity.end_char

            inside_address = any(
                start >= a and end <= b
                for a, b in address_spans
            )

            overlaps_explicit_name = any(
                start < b and end > a
                for a, b in explicit_name_spans
            )

            if inside_address or overlaps_explicit_name:
                continue

            detections.append({
                "entity_type": "PERSON",
                "text": entity.text,
                "start": start,
                "end": end,
                "score": 0.75
            })

        # 5. Add address detections
        detections.extend(address_detections)

        # 6. Resolve overlapping detections
        priority = {
            "AADHAAR": 10,
            "PAN": 10,
            "GSTIN": 10,
            "VOTER_ID": 10,
            "PASSPORT": 10,
            "ADDRESS": 9,
            "PERSON": 5
        }

        detections.sort(
            key=lambda item: (
                -priority.get(item["entity_type"], 0),
                item["start"],
                -(item["end"] - item["start"])
            )
        )

        filtered = []

        for item in detections:

            overlap = any(
                item["start"] < existing["end"]
                and item["end"] > existing["start"]
                for existing in filtered
            )

            if not overlap:
                filtered.append(item)

        return sorted(
            filtered,
            key=lambda item: item["start"]
        )


if __name__ == "__main__":

    detector = IndianPIIDetector()

    sample = """
Customer John Smith lives at:
Flat 12B, 2nd Cross,
Vijayanagar, Bengaluru, Karnataka 560040.

PAN: ABCPE1234F
"""

    findings = detector.detect(sample)

    print("\nPRIVACYGUARD AI - PII DETECTION RESULTS\n")

    for finding in findings:
        print(finding)

    print("\nTotal detections:", len(findings))
