
import re

# =====================================================
# 1. AADHAAR VERHOEFF CHECKSUM VALIDATION
# =====================================================

D_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

P_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

INV_TABLE = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_aadhaar(number: str) -> bool:
    """Check 12-digit format and Verhoeff checksum."""

    digits = re.sub(r"\s+", "", number)

    if not re.fullmatch(r"\d{12}", digits):
        return False

    # Aadhaar numbers do not start with 0 or 1.
    if digits[0] in "01":
        return False

    checksum = 0

    for i, digit in enumerate(reversed(digits)):
        value = int(digit)
        checksum = D_TABLE[checksum][P_TABLE[i % 8][value]]

    return checksum == 0


# =====================================================
# 2. PAN VALIDATION
# =====================================================

PAN_PATTERN = re.compile(
    r"^[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]$"
)


def validate_pan(number: str) -> bool:
    """Validate PAN's structural format, not its issuance."""

    number = number.strip().upper()
    return bool(PAN_PATTERN.fullmatch(number))


# =====================================================
# 3. GSTIN VALIDATION
# =====================================================

GSTIN_PATTERN = re.compile(
    r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]"
    r"[1-9A-Z]Z[0-9A-Z]$"
)


def validate_gstin(number: str) -> bool:
    """Validate GSTIN's basic 15-character structure."""

    number = number.strip().upper()
    return bool(GSTIN_PATTERN.fullmatch(number))


# =====================================================
# 4. VOTER ID / EPIC VALIDATION
# =====================================================

VOTER_ID_PATTERN = re.compile(r"^[A-Z]{3}[0-9]{7}$")


def validate_voter_id(number: str) -> bool:
    """Validate the common 10-character EPIC format."""

    number = number.strip().upper()
    return bool(VOTER_ID_PATTERN.fullmatch(number))


# =====================================================
# 5. INDIAN PASSPORT VALIDATION
# =====================================================

PASSPORT_PATTERN = re.compile(r"^[A-Z][0-9]{7}$")


def validate_passport(number: str) -> bool:
    """Validate the common Indian passport format."""

    number = number.strip().upper()
    return bool(PASSPORT_PATTERN.fullmatch(number))



from presidio_analyzer import Pattern, PatternRecognizer


def build_indian_recognizers():
    """Create custom Presidio recognizers for Indian identity numbers."""

    recognizers = []

    # Aadhaar: detect 12 digits, then validate checksum separately.
    recognizers.append(
        PatternRecognizer(
            supported_entity="AADHAAR",
            name="Indian Aadhaar Recognizer",
            patterns=[
                Pattern(
                    name="aadhaar_12_digits",
                    regex=r"(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)",
                    score=0.5,
                )
            ],
        )
    )

    # PAN
    recognizers.append(
        PatternRecognizer(
            supported_entity="PAN",
            name="Indian PAN Recognizer",
            patterns=[
                Pattern(
                    name="pan_format",
                    regex=r"\b[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]\b",
                    score=0.85,
                )
            ],
        )
    )

    # GSTIN
    recognizers.append(
        PatternRecognizer(
            supported_entity="GSTIN",
            name="Indian GSTIN Recognizer",
            patterns=[
                Pattern(
                    name="gstin_format",
                    regex=r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b",
                    score=0.85,
                )
            ],
        )
    )

    # Voter ID / EPIC
    recognizers.append(
        PatternRecognizer(
            supported_entity="VOTER_ID",
            name="Indian Voter ID Recognizer",
            patterns=[
                Pattern(
                    name="voter_id_format",
                    regex=r"\b[A-Z]{3}[0-9]{7}\b",
                    score=0.8,
                )
            ],
        )
    )

    # Indian Passport
    recognizers.append(
        PatternRecognizer(
            supported_entity="PASSPORT",
            name="Indian Passport Recognizer",
            patterns=[
                Pattern(
                    name="passport_format",
                    regex=r"\b[A-Z][0-9]{7}\b",
                    score=0.75,
                )
            ],
        )
    )

    return recognizers
