
from gateway.reinsertion import PlaceholderReinserter


def test_reordered_placeholders():

    reinserter = PlaceholderReinserter()

    mapping = {
        "<PERSON_1>": "Rahul Sharma",
        "<PAN_1>": "ABCDE1234F"
    }

    response = "PAN: <PAN_1>. Applicant: <PERSON_1>."

    result = reinserter.restore(response, mapping)

    assert result == "PAN: ABCDE1234F. Applicant: Rahul Sharma."

    print("PASS: Reordered placeholders restored correctly.")


def test_repeated_placeholders():

    reinserter = PlaceholderReinserter()

    mapping = {
        "<PERSON_1>": "Rahul Sharma"
    }

    response = "Hello <PERSON_1>. Welcome again, <PERSON_1>."

    result = reinserter.restore(response, mapping)

    assert result == "Hello Rahul Sharma. Welcome again, Rahul Sharma."

    print("PASS: Repeated placeholders restored correctly.")


def test_dropped_placeholders():

    reinserter = PlaceholderReinserter()

    mapping = {
        "<PERSON_1>": "Rahul Sharma",
        "<PAN_1>": "ABCDE1234F"
    }

    response = "Your application has been received."

    result = reinserter.restore(response, mapping)

    assert result == response

    print("PASS: Dropped placeholders do not cause incorrect restoration.")


if __name__ == "__main__":

    test_reordered_placeholders()
    test_repeated_placeholders()
    test_dropped_placeholders()

    print("\nAll reinsertion edge-case tests passed!")
