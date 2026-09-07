from google import genai

from agents.validator_agent import ValidatorAgent
from agents.evidence_agent import EvidenceAgent
from agents.target_profiler import TargetProfiler
from agents.recon.agent_router import AgentRouter
from agents.manager.agent_registry import AgentRegistry

from config.settings import GOOGLE_API_KEY, MODEL
from models.target_profile import TargetProfile


class ManagerAgent:
    """
    Central orchestration manager for BugHunter-ADK.

    Responsibilities:
        1. Maintain the Gemini connection.
        2. Register available agents.
        3. Build target profiles through TargetProfiler.
        4. Select appropriate agents based on the profile.
        5. Build a shared execution context.
        6. Execute available agents.
        7. Return a complete orchestration result.

    ReconAgent remains responsible for reconnaissance.
    TargetProfiler converts ScanResult -> TargetProfile.
    ManagerAgent uses that profile to decide what should run.
    """

    def __init__(self):

        # =================================================
        # GEMINI CONFIGURATION
        # =================================================

        self.model = MODEL

        self.client = genai.Client(
            api_key=GOOGLE_API_KEY
        )

        # =================================================
        # TARGET PROFILER
        # =================================================

        self.profiler = TargetProfiler()

        # =================================================
        # REGISTERED AGENTS
        # =================================================

        # =================================================
        # SECURITY AGENT REGISTRY
        # =================================================

        self.agent_router = AgentRouter()
        self.agent_registry = AgentRegistry()

        # Core pipeline services remain separate from
        # vulnerability-specific security agents.
        self.validator = ValidatorAgent()
        self.evidence = EvidenceAgent()

    # =====================================================
    # GEMINI CONNECTION
    # =====================================================

    def test_connection(self):
        """
        Test the Gemini API connection.

        Returns a human-readable status string.
        """

        try:

            response = self.client.models.generate_content(
                model=self.model,
                contents="Reply only with: BugHunter ADK Online"
            )

            return response.text

        except Exception as e:

            error = str(e)

            if (
                "429" in error
                or "RESOURCE_EXHAUSTED" in error
            ):
                return "Gemini unavailable"

            elif "401" in error:
                return "Invalid Gemini API key"

            elif "403" in error:
                return "Gemini access forbidden"

            elif "503" in error:
                return "Gemini service unavailable"

            return f"Gemini error: {type(e).__name__}"

    # =====================================================
    # AGENT REGISTRATION
    # =====================================================

    def register_agent(self, name, agent):
        """
        Register a single agent.
        """

        if not name:
            raise ValueError(
                "Agent name cannot be empty"
            )

        if agent is None:
            raise ValueError(
                f"Agent '{name}' cannot be None"
            )

        self.agents[name] = agent

    # =====================================================
    # REGISTER MULTIPLE AGENTS
    # =====================================================

    def register_agents(self, agents):
        """
        Register multiple agents from a dictionary.

        Example:

            manager.register_agents({
                "xss": XSSAgent(),
                "sqli": SQLiAgent()
            })
        """

        if not agents:
            return

        for name, agent in agents.items():

            self.register_agent(
                name,
                agent
            )

    # =====================================================
    # LIST REGISTERED AGENTS
    # =====================================================

    def list_agents(self):
        """
        Return all currently registered agents.
        """

        return sorted(
            self.agents.keys()
        )

    # =====================================================
    # CHECK AGENT
    # =====================================================

    def has_agent(self, name):
        """
        Determine whether an agent is registered.
        """

        return name in self.agents

    # =====================================================
    # AGENT SELECTION
    # =====================================================

    def select_agents(
        self,
        profile: TargetProfile,
    ):
        """
        Select security agents through the centralized AgentRouter.

        AgentRouter is the single source of truth for deciding
        which security agents are relevant to a target.
        """

        if not isinstance(profile, TargetProfile):
            raise TypeError(
                "profile must be a TargetProfile"
            )

        return self.agent_router.select(profile)

    # =====================================================
    # AGENT AVAILABILITY
    # =====================================================

    def get_available_agents(
        self,
        selected_agents,
    ):
        """
        Return selected agents that are registered.
        """

        return [
            name
            for name in selected_agents
            if self.agent_registry.has(name)
        ]

    # =====================================================
    # AGENTS NOT IMPLEMENTED YET
    # =====================================================

    def get_missing_agents(
        self,
        selected_agents,
    ):
        """
        Return selected agents that are not registered.
        """

        return self.agent_registry.missing(
            selected_agents
        )

    # =====================================================
    # RUN SINGLE AGENT
    # =====================================================

    def run_agent(
        self,
        name,
        context,
    ):
        """
        Execute one registered security agent.
        """

        try:
            agent = self.agent_registry.create(name)

            profile = context.get("profile")
            scan_result = context.get("scan_result")

            result = agent.run(
                scan_result=scan_result,
                target_profile=profile,
                context=context,
            )

            return {
                "agent": name,
                "status": "completed",
                "result": result,
            }

        except KeyError as e:
            return {
                "agent": name,
                "status": "not_implemented",
                "error": str(e),
            }

        except Exception as e:
            return {
                "agent": name,
                "status": "error",
                "error": str(e),
            }

    # =====================================================
    # RUN MULTIPLE AGENTS
    # =====================================================

    def run_agents(
        self,
        agent_names,
        context,
    ):
        """
        Execute selected security agents sequentially.
        """

        results = []

        for name in agent_names:
            results.append(
                self.run_agent(
                    name,
                    context,
                )
            )

        return results

    # =====================================================
    # COLLECT HYPOTHESES
    # =====================================================

    def collect_hypotheses(self, results):
        """
        Collect structured Hypothesis objects from AgentResult objects.

        This keeps hypothesis aggregation centralized in ManagerAgent
        without changing the behavior of individual security agents.
        """

        hypotheses = []

        for execution_result in results:
            if not isinstance(execution_result, dict):
                continue

            result = execution_result.get("result")

            if result is None:
                continue

            agent_hypotheses = getattr(result, "hypotheses", [])

            if not agent_hypotheses:
                continue

            hypotheses.extend(agent_hypotheses)

        return hypotheses

    # =====================================================
    # EVALUATE HYPOTHESES
    # =====================================================

    def evaluate_hypotheses(self, hypotheses, results):
        """
        Send generated hypotheses through EvidenceAgent
        and ValidatorAgent.

        Recon observations are deliberately recorded as
        non-supporting evidence. A finding is only created
        when later authorized validation produces evidence
        that actually supports the hypothesis.
        """

        evaluations = []
        findings = []

        # Index execution results by agent name.
        result_by_agent = {}

        for execution_result in results:
            if not isinstance(execution_result, dict):
                continue

            agent_name = execution_result.get("agent")

            if agent_name:
                result_by_agent[agent_name] = execution_result

        for hypothesis in hypotheses:

            if hypothesis is None:
                continue

            agent_name = getattr(
                hypothesis,
                "agent",
                "unknown"
            )

            target = getattr(
                hypothesis,
                "target",
                "unknown"
            )

            vulnerability_type = getattr(
                hypothesis,
                "vulnerability_type",
                "unknown"
            )

            execution_result = result_by_agent.get(
                agent_name,
                {}
            )

            agent_result = execution_result.get(
                "result"
            )

            observations = []

            if agent_result is not None:

                observations = list(
                    getattr(
                        agent_result,
                        "observations",
                        []
                    ) or []
                )

            # -------------------------------------------------
            # Neutral evidence.
            #
            # This is NOT proof of a vulnerability.
            # -------------------------------------------------

            evidence_description = (
                "Reconnaissance observation associated with "
                f"hypothesis '{vulnerability_type}'. "
                "No active validation evidence has been "
                "collected yet."
            )

            evidence = self.evidence.create(
                evidence_type="recon_observation",
                target=target,
                description=evidence_description,
                source_agent=agent_name,
                supports_hypothesis=False,
                confidence=0.25,
                data={
                    "hypothesis_id": getattr(
                        hypothesis,
                        "id",
                        ""
                    ),
                    "vulnerability_type": vulnerability_type,
                    "observations": observations,
                    "validation_status": "not_validated",
                },
            )

            # ValidatorAgent expects dictionaries
            # containing an evidence ID and support flag.

            evidence_dict = {
                "id": evidence.id,
                "evidence_type": evidence.evidence_type,
                "target": evidence.target,
                "description": evidence.description,
                "source_agent": evidence.source_agent,
                "supports_hypothesis": (
                    evidence.supports_hypothesis
                ),
                "confidence": evidence.confidence,
                "data": evidence.data,
            }

            validation = self.validator.validate(
                hypothesis,
                [evidence_dict]
            )

            evaluation = {
                "hypothesis": hypothesis,
                "evidence": [evidence_dict],
                "validation": validation,
            }

            evaluations.append(evaluation)

            if isinstance(validation, dict):

                finding = validation.get(
                    "finding"
                )

                if finding is not None:
                    findings.append(finding)

        return {
            "evaluations": evaluations,
            "findings": findings,
            "evaluation_count": len(evaluations),
            "finding_count": len(findings),
        }


    # =====================================================
    # BUILD TARGET PROFILE
    # =====================================================

    def build_profile(
        self,
        scan_result
    ):
        """
        Build TargetProfile from a completed ScanResult.

        TargetProfiler is now the authoritative profile
        builder.

        This replaces the old ManagerAgent profile-building
        logic that depended on obsolete TargetProfile fields.
        """

        if scan_result is None:
            raise ValueError(
                "scan_result is required to build a TargetProfile"
            )

        return self.profiler.build(
            scan_result
        )

    # =====================================================
    # CREATE SCAN PLAN
    # =====================================================

    def create_scan_plan(
        self,
        profile: TargetProfile
    ):
        """
        Create an execution plan from the TargetProfile.
        """

        if not isinstance(profile, TargetProfile):
            raise TypeError(
                "profile must be a TargetProfile"
            )

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

    # =====================================================
    # BUILD AGENT CONTEXT
    # =====================================================

    def build_agent_context(
        self,
        profile: TargetProfile,
        scan_result=None
    ):
        """
        Build the shared context passed to agents.

        The complete TargetProfile and ScanResult are included
        so future specialized agents can use the information
        discovered during reconnaissance.
        """

        if not isinstance(profile, TargetProfile):
            raise TypeError(
                "profile must be a TargetProfile"
            )

        return {

            "profile": profile,

            "scan_result": scan_result,

            "target": profile.target,

            "technologies": profile.technologies,

            "hosts": profile.hosts,

            "live_hosts": profile.live_hosts,

            "endpoints": profile.endpoints,

            "api_endpoints": profile.api_endpoints,

            "auth_endpoints": profile.auth_endpoints,

            "admin_endpoints": profile.admin_endpoints,

            "upload_endpoints": profile.upload_endpoints,

            "download_endpoints": profile.download_endpoints,

            "dashboard_endpoints": profile.dashboard_endpoints,

            "graphql_detected": profile.graphql_detected,

            "websocket_detected": profile.websocket_detected,

            "jwt_detected": profile.jwt_detected,

            "llm_detected": profile.llm_detected,

            "authentication_present": (
                profile.authentication_present
            ),

            "authorization_relevant": (
                profile.authorization_relevant
            ),

            "file_upload_present": (
                profile.file_upload_present
            ),

            "payment_related": (
                profile.payment_related
            ),

            "webhook_present": (
                profile.webhook_present
            ),

            "security_headers": (
                profile.security_headers
            ),

            "tls_information": (
                profile.tls_information
            ),

            "http_methods": (
                profile.http_methods
            ),

            "javascript_findings": (
                profile.javascript_findings
            ),

            "jwt_results": (
                profile.jwt_results
            )
        }

    # =====================================================
    # EXECUTE SCAN PLAN
    # =====================================================

    def execute_scan_plan(
        self,
        profile: TargetProfile,
        scan_result=None
    ):
        """
        Create and execute the scan plan.
        """

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

        hypotheses = self.collect_hypotheses(
            results
        )

        evaluation = self.evaluate_hypotheses(
            hypotheses,
            results
        )

        return {

            "target": profile.target,

            "plan": plan,

            "results": results,

            "hypotheses": hypotheses,

            "hypothesis_count": len(hypotheses),

            "evaluations": evaluation[
                "evaluations"
            ],

            "findings": evaluation[
                "findings"
            ],

            "evaluation_count": evaluation[
                "evaluation_count"
            ],

            "finding_count": evaluation[
                "finding_count"
            ]
        }

    # =====================================================
    # FULL ORCHESTRATION
    # =====================================================

    def run(
        self,
        target,
        scan_result=None,
        technologies=None,
        endpoints=None,
        subdomains=None
    ):
        """
        Run the complete ManagerAgent orchestration.

        New architecture:

            ScanResult
                ↓
            TargetProfiler
                ↓
            TargetProfile
                ↓
            Agent Selection
                ↓
            Scan Plan
                ↓
            Available Agents
                ↓
            Execution

        scan_result is required for the new architecture.

        The technologies/endpoints/subdomains arguments remain
        in the method signature for backwards compatibility,
        but they are no longer used to construct the profile.
        """

        # -------------------------------------------------
        # VALIDATE INPUT
        # -------------------------------------------------

        if scan_result is None:

            raise ValueError(
                "ManagerAgent.run() requires a ScanResult. "
                "Run ReconAgent first and pass the result "
                "as scan_result."
            )

        # -------------------------------------------------
        # BUILD PROFILE
        # -------------------------------------------------

        profile = self.build_profile(
            scan_result
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

        # -------------------------------------------------
        # RETURN COMPLETE RESULT
        # -------------------------------------------------

        return {

            "target": target,

            "profile": profile,

            "plan": plan,

            "execution": execution
        }
