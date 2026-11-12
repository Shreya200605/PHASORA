
from security.tripwire import PrivacyTripwire
from security.attack_detector import PlaceholderAttackDetector
from security.integrity import PlaceholderIntegrity


def test_raw_pan_blocked():

    tripwire = PrivacyTripwire()

    unsafe_payload = (
        "My PAN is ABCDE1234F"
    )

    result = tripwire.inspect(unsafe_payload)

    assert result["safe"] is False
    assert result["leakage_count"] > 0

    print("PASS: Raw PAN detected and blocked.")


def test_sanitized_payload_allowed():

    tripwire = PrivacyTripwire()

    safe_payload = (
        "My PAN is <PAN_1>"
    )

    result = tripwire.inspect(safe_payload)

    assert result["safe"] is True

    print("PASS: Sanitized placeholder accepted.")


def test_unknown_placeholder_blocked():

    detector = PlaceholderAttackDetector()

    response = "Hello <PERSON_9>"

    valid_placeholders = ["<PERSON_1>"]

    result = detector.inspect(
        response,
        valid_placeholders
    )

    assert result["safe"] is False

    print("PASS: Unknown placeholder detected.")


def test_placeholder_integrity():

    integrity = PlaceholderIntegrity()

    response = "Hello <PERSON_1>"

    valid_placeholders = ["<PERSON_1>"]

    result = integrity.inspect(
        response,
        valid_placeholders
    )

    assert result["safe"] is True

    print("PASS: Valid placeholder integrity verified.")


if __name__ == "__main__":

    test_raw_pan_blocked()
    test_sanitized_payload_allowed()
    test_unknown_placeholder_blocked()
    test_placeholder_integrity()

    print("\nAll security tests passed!")
