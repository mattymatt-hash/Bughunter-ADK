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

        response = self.manager.client.models.generate_content(
            model=self.manager.model,
            contents=prompt,
        )

        return response.text