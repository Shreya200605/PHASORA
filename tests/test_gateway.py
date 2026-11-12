
from detection.detector import PIIDetector
from gateway.processor import GatewayProcessor
from gateway.reinsertion import PlaceholderReinserter


class MockLLM:

    model = "PHASORA-Mock-LLM"

    def generate(self, text):
        print("\nOutbound prompt received by mock LLM:")
        print(text)
        return "Hello <PERSON_1>, your PAN <PAN_1> has been received."


class IsolationMockLLM:

    model = "PHASORA-Isolation-Test"

    def generate(self, text):
        print("\nIsolation test outbound prompt:")
        print(text)
        return "Hello <PERSON_1>."


class AttackMockLLM:

    model = "PHASORA-Attack-Test"

    def generate(self, text):
        print("\nAdversarial LLM outbound prompt:")
        print(text)
        return "Hello <PERSON_9>."


class StaticPersonDetector:

    def detect(self, text):
        names = ["Rahul Sharma", "Ananya Rao"]

        for name in names:
            start = text.find(name)

            if start != -1:
                return [{
                    "entity_type": "PERSON",
                    "start": start,
                    "end": start + len(name),
                    "score": 1.0,
                    "value": name
                }]

        return []


class TrackingReinserter:

    def __init__(self):
        self.restore_calls = 0
        self.original_reinserter = PlaceholderReinserter()

    def restore(self, response, mapping):
        self.restore_calls += 1
        return self.original_reinserter.restore(response, mapping)


def test_gateway():

    gateway = GatewayProcessor(
        PIIDetector(),
        MockLLM(),
        PlaceholderReinserter()
    )

    prompt = (
        "My name is Rahul Sharma "
        "and my PAN is ABCDE1234F. "
        "Please help with my application."
    )

    result = gateway.process(prompt, purpose="loan")

    print("\nOriginal prompt:")
    print(result["original_prompt"])

    print("\nSanitized prompt:")
    print(result["sanitized_prompt"])

    print("\nFinal restored response:")
    print(result["final_response"])

    print("\nOutbound security:")
    print(result["security"])

    print("\nResponse security:")
    print(result["response_security"])

    print("\nPrivacy release receipt:")
    print(result["receipt"])

    assert result["security"]["approved"] is True
    assert "Rahul Sharma" not in result["sanitized_prompt"]
    assert "Rahul Sharma" in result["final_response"]
    assert result["response_security"]["mapping_integrity"]["safe"] is True
    assert result["receipt"]["mapping_integrity"] == "VERIFIED"

    print("\nPASS: Standard gateway integration.")
    print("PASS: HMAC mapping integrity verified in gateway.")


def test_cross_request_isolation():

    gateway = GatewayProcessor(
        StaticPersonDetector(),
        IsolationMockLLM(),
        PlaceholderReinserter()
    )

    first_result = gateway.process(
        "My name is Rahul Sharma.",
        purpose="loan"
    )

    second_result = gateway.process(
        "My name is Ananya Rao.",
        purpose="loan"
    )

    assert "<PERSON_1>" in first_result["sanitized_prompt"]
    assert "<PERSON_1>" in second_result["sanitized_prompt"]
    assert first_result["final_response"] == "Hello Rahul Sharma."
    assert second_result["final_response"] == "Hello Ananya Rao."
    assert "Ananya Rao" not in first_result["final_response"]
    assert "Rahul Sharma" not in second_result["final_response"]

    print("\nPASS: Both requests independently generated PERSON_1.")
    print("PASS: Request 1 restored Rahul Sharma.")
    print("PASS: Request 2 restored Ananya Rao.")
    print("PASS: No cross-request identity leakage.")


def test_gateway_hmac_tampering():

    reinserter = TrackingReinserter()

    gateway = GatewayProcessor(
        StaticPersonDetector(),
        IsolationMockLLM(),
        reinserter
    )

    gateway.privacy_controller.integrity.verify_mapping = (
        lambda mapping, signature, secret: False
    )

    try:
        gateway.process(
            "My name is Rahul Sharma.",
            purpose="loan"
        )

        raise AssertionError("Gateway accepted a tampered mapping.")

    except ValueError as error:
        assert (
            "Placeholder mapping integrity verification failed."
            in str(error)
        )

    assert reinserter.restore_calls == 0

    print("\nPASS: Gateway rejected failed HMAC verification.")
    print("PASS: Original identity was not restored.")


def test_unknown_placeholder_attack():

    reinserter = TrackingReinserter()

    gateway = GatewayProcessor(
        StaticPersonDetector(),
        AttackMockLLM(),
        reinserter
    )

    try:
        gateway.process(
            "My name is Rahul Sharma.",
            purpose="loan"
        )

        raise AssertionError("Gateway accepted an unknown placeholder.")

    except ValueError as error:
        assert (
            "LLM response failed placeholder security checks."
            in str(error)
        )

    assert reinserter.restore_calls == 0

    print("\nPASS: Unknown LLM placeholder rejected.")
    print("PASS: Reinsertion was blocked.")


if __name__ == "__main__":

    test_gateway()
    test_cross_request_isolation()
    test_gateway_hmac_tampering()
    test_unknown_placeholder_attack()

    print("\nAll four gateway tests passed!")
