import os
import requests
from dotenv import load_dotenv

load_dotenv()


class LLMBackend:

    def generate(self, text):
        raise NotImplementedError(
            "LLM provider must implement generate()."
        )


class OpenAIBackend(LLMBackend):

    def __init__(self, model="gpt-4o-mini"):

        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model = model

        if not self.api_key:
            raise ValueError(
                "OPENAI_API_KEY is missing from the environment."
            )

    def generate(self, text):

        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": self.model,
                "messages": [
                    {
                        "role": "user",
                        "content": text
                    }
                ],
                "temperature": 0.2
            },
            timeout=60
        )

        response.raise_for_status()

        result = response.json()

        return result["choices"][0]["message"]["content"]