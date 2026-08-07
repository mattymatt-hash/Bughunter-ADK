from agents.manager.manager import ManagerAgent


class AIAnalyzer:

    def __init__(self):
        self.manager = ManagerAgent()

    def analyze(self, result):

        prompt = f"""
You are a senior penetration tester.

Analyze this reconnaissance information.

Target: {result.target}

IP: {result.ip}

HTTP Status: {result.status}

Title: {result.title}

Server: {result.server}

robots.txt: {result.robots}

sitemap.xml: {result.sitemap}

Technologies:

{", ".join(result.technologies)}

Give:

1. Executive Summary

2. Interesting Technologies

3. Possible Attack Surface

4. Recommended Next Steps

Keep it under 300 words.
"""

        try:

            response = self.manager.client.models.generate_content(
                model=self.manager.model,
                contents=prompt,
            )

            return response.text

        except Exception as e:

            error = str(e)

            print()
            print("========== AI ANALYZER ==========")

            if "429" in error or "RESOURCE_EXHAUSTED" in error:

                print("Gemini quota exceeded.")
                print("Skipping AI analysis.")

                message = (
                    "AI analysis skipped.\n\n"
                    "Reason: Gemini quota exceeded."
                )

            elif "401" in error:

                print("Invalid Gemini API key.")
                print("Skipping AI analysis.")

                message = (
                    "AI analysis skipped.\n\n"
                    "Reason: Invalid Gemini API key."
                )

            elif "403" in error:

                print("Gemini request forbidden.")
                print("Skipping AI analysis.")

                message = (
                    "AI analysis skipped.\n\n"
                    "Reason: Access forbidden."
                )

            elif "503" in error:

                print("Gemini service unavailable.")
                print("Skipping AI analysis.")

                message = (
                    "AI analysis skipped.\n\n"
                    "Reason: Gemini service unavailable."
                )

            else:

                print(type(e).__name__)
                print(error)

                message = (
                    "AI analysis skipped.\n\n"
                    f"Reason: {type(e).__name__}"
                )

            print("================================")
            print()

            return message