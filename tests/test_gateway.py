
import re

from gateway.processor import GatewayProcessor
from gateway.reinsertion import PlaceholderReinserter


class StaticPersonDetector:
    TEST_ENTITIES = [
        ("PERSON", "Rahul Sharma"),
        ("PERSON", "Priya Nair"),
        ("PAN", "ABCPA1234F"),
        ("PAN", "PQTPA1234F"),
    ]

    def detect(self, text):
        findings = []

        for entity_type, value in self.TEST_ENTITIES:
            for match in re.finditer(re.escape(value), text):
                findings.append({
                    "entity_type": entity_type,
                    "text": value,
                    "value": value,
                    "start": match.start(),
                    "end": match.end(),
                    "score": 1.0
                })

        return sorted(findings, key=lambda item: item["start"])


class MockLLM:
    model = "PHASORA-Mock-LLM"

    def generate(self, prompt):
        return "Processed request: " + prompt


def create_gateway():
    return GatewayProcessor(
        detector=StaticPersonDetector(),
        llm_client=MockLLM(),
        reinserter=PlaceholderReinserter()
    )


def test_standard_gateway():
    print("\nTEST 1: Standard gateway processing")

    prompt = (
        "My name is Rahul Sharma and my PAN is ABCPA1234F. "
        "Please help with my application."
    )

    result = create_gateway().process(prompt, purpose="loan")

    assert "Rahul Sharma" not in result["sanitized_prompt"]
    assert "ABCPA1234F" not in result["sanitized_prompt"]
    assert "<PERSON_1>" in result["sanitized_prompt"]
    assert "<PAN_1>" in result["sanitized_prompt"]

    assert "Rahul Sharma" in result["final_response"]
    assert "ABCPA1234F" in result["final_response"]
    assert result["security"]["approved"] is True
    assert result["response_security"]["mapping_integrity"]["safe"] is True

    print("PASS: Person and PAN were masked.")
    print("PASS: Placeholders were restored locally.")
    print("PASS: Outbound security approved the request.")
    print("PASS: Mapping integrity was verified.")


def test_repeated_entities():
    print("\nTEST 2: Repeated entity handling")

    prompt = (
        "Rahul Sharma submitted the form. "
        "Please contact Rahul Sharma about PAN ABCPA1234F. "
        "The PAN ABCPA1234F belongs to Rahul Sharma."
    )

    result = create_gateway().process(prompt, purpose="loan")
    sanitized = result["sanitized_prompt"]
    restored = result["final_response"]

    assert sanitized.count("<PERSON_1>") == 3
    assert sanitized.count("<PAN_1>") == 2
    assert "<PERSON_2>" not in sanitized
    assert "<PAN_2>" not in sanitized

    assert restored.count("Rahul Sharma") == 3
    assert restored.count("ABCPA1234F") == 2

    print("PASS: Repeated names reuse the same placeholder.")
    print("PASS: Repeated PAN values reuse the same placeholder.")
    print("PASS: All repeated values were restored correctly.")


def test_cross_request_isolation():
    print("\nTEST 3: Cross-request isolation")

    gateway = create_gateway()

    first = gateway.process(
        "My name is Rahul Sharma and my PAN is ABCPA1234F.",
        purpose="loan"
    )

    second = gateway.process(
        "My name is Priya Nair and my PAN is PQTPA1234F.",
        purpose="loan"
    )

    assert "Rahul Sharma" in first["final_response"]
    assert "ABCPA1234F" in first["final_response"]

    assert "Priya Nair" in second["final_response"]
    assert "PQTPA1234F" in second["final_response"]

    assert "Rahul Sharma" not in second["final_response"]
    assert "ABCPA1234F" not in second["final_response"]

    assert "Priya Nair" not in second["sanitized_prompt"]
    assert "PQTPA1234F" not in second["sanitized_prompt"]

    assert second["security"]["approved"] is True
    assert second["response_security"]["mapping_integrity"]["safe"] is True

    print("PASS: First request mapping remained isolated.")
    print("PASS: Second request used its own mapping.")
    print("PASS: No previous request values leaked.")


if __name__ == "__main__":
    test_standard_gateway()
    test_repeated_entities()
    test_cross_request_isolation()

    print("\nALL GATEWAY TESTS PASSED!")
