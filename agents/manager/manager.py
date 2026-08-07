from google import genai

from config.settings import GOOGLE_API_KEY, MODEL


class ManagerAgent:

    def __init__(self):

        self.model = MODEL

        self.client = genai.Client(
            api_key=GOOGLE_API_KEY
        )

    def test_connection(self):

        try:

            response = self.client.models.generate_content(
                model=self.model,
                contents="Reply only with: BugHunter ADK Online"
            )

            return response.text

        except Exception as e:

            error = str(e)

            if "429" in error or "RESOURCE_EXHAUSTED" in error:
                return "Gemini unavailable"

            elif "401" in error:
                return "Invalid Gemini API key"

            elif "403" in error:
                return "Gemini access forbidden"

            elif "503" in error:
                return "Gemini service unavailable"

            return f"Gemini error: {type(e).__name__}"