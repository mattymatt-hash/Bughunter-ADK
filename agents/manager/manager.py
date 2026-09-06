from google import genai
from agents.validator_agent import ValidatorAgent
from agents.evidence_agent import EvidenceAgent
from config.settings import GOOGLE_API_KEY, MODEL
from models.target_profile import TargetProfile


class ManagerAgent:

    def __init__(self):

        self.model = MODEL

        self.client = genai.Client(
            api_key=GOOGLE_API_KEY
        )

        # =================================================
        # REGISTERED SPECIALIZED AGENTS
        # =================================================
        self.agents = {}

        self.register_agent(
            "validator",
            ValidatorAgent()
        )

        self.register_agent(
            "evidence",
            EvidenceAgent()
        )

    # =================================================
    # GEMINI CONNECTION
    # =================================================

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

    # =================================================
    # AGENT REGISTRATION
    # =================================================

    def register_agent(self, name, agent):

        if not name:
            raise ValueError("Agent name cannot be empty")

        if agent is None:
            raise ValueError(
                f"Agent '{name}' cannot be None"
            )

        self.agents[name] = agent

    # =================================================
    # REGISTER MULTIPLE AGENTS
    # =================================================

    def register_agents(self, agents):

        for name, agent in agents.items():

            self.register_agent(
                name,
                agent
            )

    # =================================================
    # LIST REGISTERED AGENTS
    # =================================================

    def list_agents(self):

        return sorted(
            self.agents.keys()
        )

    # =================================================
    # CHECK AGENT
    # =================================================

    def has_agent(self, name):

        return name in self.agents

    # =================================================
    # AGENT SELECTION
    # =================================================

    def select_agents(
        self,
        profile: TargetProfile
    ):

        selected = []

        # -------------------------------------------------
        # APPLICATION REVIEW
        # -------------------------------------------------

        selected.append(
            "app_review"
        )

        # -------------------------------------------------
        # AUTHENTICATION
        # -------------------------------------------------

        if profile.auth_present:

            selected.append("auth")
            selected.append("idor")
            selected.append("business_logic")

        # -------------------------------------------------
        # API
        # -------------------------------------------------

        if profile.api_present:

            selected.append("api")
            selected.append("idor")
            selected.append("auth")

        # -------------------------------------------------
        # GRAPHQL
        # -------------------------------------------------

        if profile.graphql_present:

            selected.append(
                "graphql"
            )

        # -------------------------------------------------
        # WEBSOCKETS
        # -------------------------------------------------

        if profile.websocket_present:

            selected.append(
                "websocket"
            )

        # -------------------------------------------------
        # FILE UPLOADS
        # -------------------------------------------------

        if profile.file_uploads:

            selected.append(
                "file_upload"
            )

        # -------------------------------------------------
        # LLM
        # -------------------------------------------------

        if profile.llm_present:

            selected.append(
                "llm_security"
            )

        # -------------------------------------------------
        # GENERAL WEB TESTING
        # -------------------------------------------------

        selected.extend([
            "xss",
            "sqli",
            "ssrf",
            "csrf",
            "cors"
        ])

        # -------------------------------------------------
        # REMOVE DUPLICATES
        # -------------------------------------------------

        return list(
            dict.fromkeys(selected)
        )

    # =================================================
    # AGENT AVAILABILITY
    # =================================================

    def get_available_agents(
        self,
        selected_agents
    ):

        return [
            name
            for name in selected_agents
            if self.has_agent(name)
        ]

    # =================================================
    # AGENTS NOT IMPLEMENTED YET
    # =================================================

    def get_missing_agents(
        self,
        selected_agents
    ):

        return [
            name
            for name in selected_agents
            if not self.has_agent(name)
        ]

    # =================================================
    # RUN SINGLE AGENT
    # =================================================

    def run_agent(
        self,
        name,
        context
    ):

        agent = self.agents.get(name)

        if not agent:

            return {
                "agent": name,
                "status": "not_implemented"
            }

        try:

            result = agent.run(
                context
            )

            return {
                "agent": name,
                "status": "completed",
                "result": result
            }

        except Exception as e:

            return {
                "agent": name,
                "status": "error",
                "error": str(e)
            }

    # =================================================
    # RUN MULTIPLE AGENTS
    # =================================================

    def run_agents(
        self,
        agent_names,
        context
    ):

        results = []

        for name in agent_names:

            result = self.run_agent(
                name,
                context
            )

            results.append(
                result
            )

        return results

    # =================================================
    # BUILD TARGET PROFILE
    # =================================================

    def build_profile(
        self,
        target,
        technologies=None,
        endpoints=None,
        subdomains=None
    ):

        technologies = technologies or []
        endpoints = endpoints or []
        subdomains = subdomains or []

        technology_text = " ".join(
            str(x).lower()
            for x in technologies
        )

        endpoint_text = " ".join(
            str(x).lower()
            for x in endpoints
        )

        profile = TargetProfile(

            target=target,

            technologies=technologies,

            endpoints=endpoints,

            subdomains=subdomains,

            # -------------------------------------------------
            # API
            # -------------------------------------------------

            api_present=(
                "api" in endpoint_text
                or "graphql" in technology_text
                or "rest" in technology_text
            ),

            # -------------------------------------------------
            # GRAPHQL
            # -------------------------------------------------

            graphql_present=(
                "graphql" in technology_text
                or "graphql" in endpoint_text
            ),

            # -------------------------------------------------
            # WEBSOCKET
            # -------------------------------------------------

            websocket_present=(
                "websocket" in technology_text
                or "ws://" in endpoint_text
                or "wss://" in endpoint_text
            ),

            # -------------------------------------------------
            # LLM
            # -------------------------------------------------

            llm_present=(
                "openai" in technology_text
                or "gemini" in technology_text
                or "anthropic" in technology_text
                or "llm" in technology_text
            )
        )

        return profile

    # =================================================
    # CREATE SCAN PLAN
    # =================================================

    def create_scan_plan(
        self,
        profile: TargetProfile
    ):

        selected = self.select_agents(
            profile
        )

        available = self.get_available_agents(
            selected
        )

        missing = self.get_missing_agents(
            selected
        )

        return {

            "target": profile.target,

            "agents": selected,

            "available_agents": available,

            "missing_agents": missing,

            "agent_count": len(selected),

            "available_count": len(available),

            "missing_count": len(missing)
        }

    # =================================================
    # BUILD AGENT CONTEXT
    # =================================================

    def build_agent_context(
        self,
        profile,
        scan_result=None
    ):

        return {

            "profile": profile,

            "scan_result": scan_result,

            "target": profile.target,

            "technologies": profile.technologies,

            "endpoints": profile.endpoints,

            "subdomains": profile.subdomains
        }

    # =================================================
    # EXECUTE SCAN PLAN
    # =================================================

    def execute_scan_plan(
        self,
        profile,
        scan_result=None
    ):

        plan = self.create_scan_plan(
            profile
        )

        context = self.build_agent_context(
            profile,
            scan_result
        )

        results = self.run_agents(
            plan["available_agents"],
            context
        )

        return {

            "target": profile.target,

            "plan": plan,

            "results": results
        }

    # =================================================
    # FULL ORCHESTRATION
    # =================================================

    def run(
        self,
        target,
        scan_result=None,
        technologies=None,
        endpoints=None,
        subdomains=None
    ):

        # -------------------------------------------------
        # BUILD PROFILE
        # -------------------------------------------------

        profile = self.build_profile(
            target=target,
            technologies=technologies,
            endpoints=endpoints,
            subdomains=subdomains
        )

        # -------------------------------------------------
        # CREATE PLAN
        # -------------------------------------------------

        plan = self.create_scan_plan(
            profile
        )

        # -------------------------------------------------
        # EXECUTE
        # -------------------------------------------------

        execution = self.execute_scan_plan(
            profile=profile,
            scan_result=scan_result
        )

        return {

            "target": target,

            "profile": profile,

            "plan": plan,

            "execution": execution
        }