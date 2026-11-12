
from security.tripwire import PrivacyTripwire
from security.attack_detector import PlaceholderAttackDetector
from security.integrity import PlaceholderIntegrity
from security.privacy_controller import PrivacyController


def test_raw_pan_blocked():

    tripwire = PrivacyTripwire()
    result = tripwire.inspect("My PAN is ABCDE1234F")

    assert result["safe"] is False
    assert result["leakage_count"] > 0

    print("PASS: Raw PAN detected and blocked.")


def test_sanitized_payload_allowed():

    tripwire = PrivacyTripwire()
    result = tripwire.inspect("My PAN is <PAN_1>")

    assert result["safe"] is True

    print("PASS: Sanitized placeholder accepted.")


def test_unknown_placeholder_blocked():

    detector = PlaceholderAttackDetector()

    result = detector.inspect(
        "Hello <PERSON_9>",
        ["<PERSON_1>"]
    )

    assert result["safe"] is False

    print("PASS: Unknown placeholder detected.")


def test_placeholder_integrity():

    integrity = PlaceholderIntegrity()

    result = integrity.inspect(
        "Hello <PERSON_1>",
        ["<PERSON_1>"]
    )

    assert result["safe"] is True

    print("PASS: Valid placeholder integrity verified.")


def test_original_name_leak_blocked():

    controller = PrivacyController()

    entities = [{
        "entity_type": "PERSON",
        "value": "Rahul Sharma",
        "start": 12,
        "end": 24
    }]

    decisions = [{
        "entity_type": "PERSON",
        "action": "MASK",
        "purpose": "loan"
    }]

    result = controller.validate_outbound(
        "My name is Rahul Sharma",
        entities,
        decisions
    )

    assert result["approved"] is False
    assert result["leakage_count"] > 0

    print("PASS: Original name leakage blocked.")


def test_masked_name_allowed():

    controller = PrivacyController()

    entities = [{
        "entity_type": "PERSON",
        "value": "Rahul Sharma",
        "start": 12,
        "end": 24
    }]

    decisions = [{
        "entity_type": "PERSON",
        "action": "MASK",
        "purpose": "loan"
    }]

    result = controller.validate_outbound(
        "My name is <PERSON_1>",
        entities,
        decisions
    )

    assert result["approved"] is True
    assert result["leakage_count"] == 0

    print("PASS: Masked name accepted.")


def test_hmac_mapping_valid():

    integrity = PlaceholderIntegrity()

    secret = "PHASORA_TEST_SECRET"

    mapping = {
        "<PERSON_1>": "Rahul Sharma",
        "<PAN_1>": "ABCDE1234F"
    }

    signature = integrity.sign_mapping(
        mapping,
        secret
    )

    result = integrity.verify_mapping(
        mapping,
        signature,
        secret
    )

    assert result is True

    print("PASS: Valid HMAC mapping verified.")


def test_hmac_mapping_tampering():

    integrity = PlaceholderIntegrity()

    secret = "PHASORA_TEST_SECRET"

    original_mapping = {
        "<PERSON_1>": "Rahul Sharma",
        "<PAN_1>": "ABCDE1234F"
    }

    signature = integrity.sign_mapping(
        original_mapping,
        secret
    )

    tampered_mapping = {
        "<PERSON_1>": "Ananya Rao",
        "<PAN_1>": "ABCDE1234F"
    }

    result = integrity.verify_mapping(
        tampered_mapping,
        signature,
        secret
    )

    assert result is False

    print("PASS: Tampered HMAC mapping rejected.")


if __name__ == "__main__":

    test_raw_pan_blocked()
    test_sanitized_payload_allowed()
    test_unknown_placeholder_blocked()
    test_placeholder_integrity()
    test_original_name_leak_blocked()
    test_masked_name_allowed()
    test_hmac_mapping_valid()
    test_hmac_mapping_tampering()

    print("\nAll eight security tests passed!")
