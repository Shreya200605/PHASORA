
from detection.detector import PIIDetector
from gateway.processor import GatewayProcessor
from gateway.reinsertion import PlaceholderReinserter


class MockLLM:

    model = "PHASORA-Mock-LLM"

    def generate(self, text):

        print("\nOutbound prompt received by mock LLM:")
        print(text)

        return (
            "Hello <PERSON_1>, "
            "your PAN <PAN_1> has been received."
        )


def main():

    detector = PIIDetector()
    llm = MockLLM()
    reinserter = PlaceholderReinserter()

    gateway = GatewayProcessor(
        detector,
        llm,
        reinserter
    )

    prompt = (
        "My name is Rahul Sharma "
        "and my PAN is ABCDE1234F. "
        "Please help with my application."
    )

    result = gateway.process(
        prompt,
        purpose="loan"
    )

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


if __name__ == "__main__":
    main()
