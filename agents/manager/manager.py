from google import genai

from config.settings import GOOGLE_API_KEY, MODEL


class ManagerAgent:

    def __init__(self):

        self.model = MODEL

        self.client = genai.Client(
            api_key=GOOGLE_API_KEY
        )

    def test_connection(self):

        response = self.client.models.generate_content(
            model=self.model,
            contents="Reply only with: BugHunter ADK Online"
        )

        return response.text