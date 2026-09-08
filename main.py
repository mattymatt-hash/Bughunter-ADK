import sys

from rich.console import Console

from config.settings import APP_NAME
from database.database import init_database

from agents.manager.manager import ManagerAgent
from agents.manager.ai_analyzer import AIAnalyzer
from agents.recon.recon_agent import ReconAgent
from agents.recon.report_writer import ReportWriter


console = Console()


# =========================================================
# BANNER
# =========================================================

def banner():
    """
    Display the BugHunter-ADK startup banner.
    """

    console.print()
    console.print(
        "[bold cyan]==============================================[/bold cyan]"
    )
    console.print(
        f"[bold cyan]             {APP_NAME}[/bold cyan]"
    )
    console.print(
        "[bold cyan]==============================================[/bold cyan]"
    )
    console.print()


# =========================================================
# STARTUP
# =========================================================

def startup():
    """
    Initialize the database and verify the Manager/Gemini
    connection.
    """

    console.print(
        "[cyan]Initializing database...[/cyan]"
    )

    init_database()

    console.print(
        "[green]✓ Database initialized[/green]"
    )

    console.print(
        "[cyan]Connecting to Gemini...[/cyan]"
    )

    manager = ManagerAgent()

    connection = manager.test_connection()

    if connection == "BugHunter ADK Online":

        console.print(
            "[green]✓ BugHunter ADK Online[/green]"
        )

    elif connection == "Gemini unavailable":

        console.print(
            "[yellow]⚠ Gemini unavailable[/yellow]"
        )

    elif connection == "Invalid Gemini API key":

        console.print(
            "[red]✗ Invalid Gemini API key[/red]"
        )

    elif connection == "Gemini access forbidden":

        console.print(
            "[red]✗ Gemini access forbidden[/red]"
        )

    elif connection == "Gemini service unavailable":

        console.print(
            "[yellow]⚠ Gemini service unavailable[/yellow]"
        )

    else:

        console.print(
            f"[yellow]⚠ {connection}[/yellow]"
        )

    return manager


# =========================================================
# DISPLAY RECON RESULTS
# =========================================================

def display_scan_result(result):
    """
    Display the primary reconnaissance results.
    """

    console.print()
    console.print(
        "[bold cyan]──────────────────────────────────────────────[/bold cyan]"
    )
    console.print(
        "[bold cyan]                 Scan Results[/bold cyan]"
    )
    console.print(
        "[bold cyan]──────────────────────────────────────────────[/bold cyan]"
    )

    console.print()

    # -----------------------------------------------------
    # TARGET
    # -----------------------------------------------------

    if hasattr(result, "target"):

        console.print(
            f"[bold]Target:[/bold] {result.target}"
        )

    # -----------------------------------------------------
    # HOSTS
    # -----------------------------------------------------

    if hasattr(result, "hosts"):

        console.print(
            f"[bold]Hosts:[/bold] {len(result.hosts)}"
        )

    # -----------------------------------------------------
    # URLS
    # -----------------------------------------------------

    if hasattr(result, "urls"):

        console.print(
            f"[bold]URLs:[/bold] {len(result.urls)}"
        )

    # -----------------------------------------------------
    # TECHNOLOGIES
    # -----------------------------------------------------

    if hasattr(result, "technologies"):

        technologies = result.technologies or []

        console.print(
            f"[bold]Technologies:[/bold] "
            f"{len(technologies)}"
        )

        for technology in technologies[:20]:

            console.print(
                f"  • {technology}"
            )

    # -----------------------------------------------------
    # JAVASCRIPT FINDINGS
    # -----------------------------------------------------

    if hasattr(result, "javascript_findings"):

        findings = result.javascript_findings or []

        console.print(
            f"[bold]JavaScript Findings:[/bold] "
            f"{len(findings)}"
        )

    # -----------------------------------------------------
    # JWT RESULTS
    # -----------------------------------------------------

    if hasattr(result, "jwt_results"):

        jwt_results = result.jwt_results or []

        console.print(
            f"[bold]JWT Results:[/bold] "
            f"{len(jwt_results)}"
        )

    console.print()


# =========================================================
# DISPLAY TARGET PROFILE
# =========================================================

def display_target_profile(profile):
    """
    Display the TargetProfile generated by TargetProfiler.
    """

    console.print()

    console.print(
        "[bold cyan]──────────────────────────────────────────────[/bold cyan]"
    )
    console.print(
        "[bold cyan]               Target Profile[/bold cyan]"
    )
    console.print(
        "[bold cyan]──────────────────────────────────────────────[/bold cyan]"
    )

    console.print()

    console.print(
        f"[bold]Target:[/bold] {profile.target}"
    )

    console.print(
        f"[bold]Technologies:[/bold] "
        f"{len(profile.technologies)}"
    )

    console.print(
        f"[bold]Hosts:[/bold] "
        f"{len(profile.hosts)}"
    )

    console.print(
        f"[bold]Live Hosts:[/bold] "
        f"{len(profile.live_hosts)}"
    )

    console.print(
        f"[bold]Endpoints:[/bold] "
        f"{len(profile.endpoints)}"
    )

    console.print(
        f"[bold]API Endpoints:[/bold] "
        f"{len(profile.api_endpoints)}"
    )

    console.print(
        f"[bold]Auth Endpoints:[/bold] "
        f"{len(profile.auth_endpoints)}"
    )

    console.print(
        f"[bold]Admin Endpoints:[/bold] "
        f"{len(profile.admin_endpoints)}"
    )

    console.print(
        f"[bold]Upload Endpoints:[/bold] "
        f"{len(profile.upload_endpoints)}"
    )

    console.print(
        f"[bold]Download Endpoints:[/bold] "
        f"{len(profile.download_endpoints)}"
    )

    console.print(
        f"[bold]Dashboard Endpoints:[/bold] "
        f"{len(profile.dashboard_endpoints)}"
    )

    console.print()

    console.print(
        f"[bold]GraphQL:[/bold] "
        f"{'Detected' if profile.graphql_detected else 'Not detected'}"
    )

    console.print(
        f"[bold]WebSocket:[/bold] "
        f"{'Detected' if profile.websocket_detected else 'Not detected'}"
    )

    console.print(
        f"[bold]JWT:[/bold] "
        f"{'Detected' if profile.jwt_detected else 'Not detected'}"
    )

    console.print(
        f"[bold]LLM:[/bold] "
        f"{'Detected' if profile.llm_detected else 'Not detected'}"
    )

    console.print(
        f"[bold]Authentication:[/bold] "
        f"{'Present' if profile.authentication_present else 'Not detected'}"
    )

    console.print(
        f"[bold]Authorization Relevant:[/bold] "
        f"{'Yes' if profile.authorization_relevant else 'No'}"
    )

    console.print(
        f"[bold]File Upload:[/bold] "
        f"{'Present' if profile.file_upload_present else 'Not detected'}"
    )

    console.print(
        f"[bold]Payment Related:[/bold] "
        f"{'Detected' if profile.payment_related else 'Not detected'}"
    )

    console.print(
        f"[bold]Webhook:[/bold] "
        f"{'Detected' if profile.webhook_present else 'Not detected'}"
    )

    console.print()


# =========================================================
# DISPLAY SCAN PLAN
# =========================================================

def display_scan_plan(plan):
    """
    Display the agent execution plan.
    """

    console.print(
        "[bold cyan]──────────────────────────────────────────────[/bold cyan]"
    )
    console.print(
        "[bold cyan]                 Scan Plan[/bold cyan]"
    )
    console.print(
        "[bold cyan]──────────────────────────────────────────────[/bold cyan]"
    )

    console.print()

    console.print(
        f"[bold]Total selected agents:[/bold] "
        f"{plan['agent_count']}"
    )

    console.print(
        f"[bold]Available agents:[/bold] "
        f"{plan['available_count']}"
    )

    console.print(
        f"[bold]Not implemented:[/bold] "
        f"{plan['missing_count']}"
    )

    console.print()

    if plan["agents"]:

        console.print(
            "[bold]Selected Agents:[/bold]"
        )

        for agent in plan["agents"]:

            if agent in plan["available_agents"]:

                console.print(
                    f"  [green]✓[/green] {agent}"
                )

            else:

                console.print(
                    f"  [yellow]○[/yellow] {agent}"
                )

    console.print()


# =========================================================
# DISPLAY AGENT EXECUTION
# =========================================================

def display_execution(execution):
    """
    Display the results from currently implemented agents.
    """

    console.print(
        "[bold cyan]──────────────────────────────────────────────[/bold cyan]"
    )
    console.print(
        "[bold cyan]              Agent Execution[/bold cyan]"
    )
    console.print(
        "[bold cyan]──────────────────────────────────────────────[/bold cyan]"
    )

    console.print()

    results = execution.get(
        "results",
        []
    )

    if not results:

        console.print(
            "[yellow]No implemented agents were executed.[/yellow]"
        )

        return

    for item in results:

        agent = item.get(
            "agent",
            "unknown"
        )

        status = item.get(
            "status",
            "unknown"
        )

        if status == "completed":

            console.print(
                f"[green]✓[/green] {agent}: completed"
            )

        elif status == "error":

            console.print(
                f"[red]✗[/red] {agent}: "
                f"{item.get('error', 'unknown error')}"
            )

        else:

            console.print(
                f"[yellow]○[/yellow] {agent}: {status}"
            )

    console.print()


# =========================================================
# AI ANALYSIS
# =========================================================

def run_ai_analysis(result):
    """
    Run the optional Gemini AI analysis.

    AI analysis must never cause the entire scan to fail.
    """

    console.print(
        "[bold cyan]──────────────────────────────────────────────[/bold cyan]"
    )
    console.print(
        "[bold cyan]             AI Security Assessment[/bold cyan]"
    )
    console.print(
        "[bold cyan]──────────────────────────────────────────────[/bold cyan]"
    )

    console.print()

    try:

        analyzer = AIAnalyzer()

        analysis = analyzer.analyze(
            result
        )

        if analysis:

            console.print(
                analysis
            )

        else:

            console.print(
                "[yellow]No AI analysis returned.[/yellow]"
            )

    except Exception as e:

        error = str(e)

        if (
            "429" in error
            or "RESOURCE_EXHAUSTED" in error
            or "quota" in error.lower()
        ):

            console.print(
                "[yellow]Gemini quota exceeded. "
                "Skipping AI analysis.[/yellow]"
            )

        else:

            console.print(
                f"[yellow]AI analysis skipped: "
                f"{type(e).__name__}: {error}[/yellow]"
            )

    console.print()


# =========================================================
# SAVE REPORT
# =========================================================

def save_report(result):
    """
    Save the reconnaissance report.

    The existing ReportWriter remains responsible for the
    base ScanResult report.
    """

    writer = ReportWriter()

    filename = writer.save(
        result
    )

    console.print(
        f"[green]✓ Report saved:[/green] {filename}"
    )

    return filename


# =========================================================
# MAIN
# =========================================================

def main():

    banner()

    # -----------------------------------------------------
    # STARTUP
    # -----------------------------------------------------

    manager = startup()

    # -----------------------------------------------------
    # ARGUMENT VALIDATION
    # -----------------------------------------------------

    if (
        len(sys.argv) < 3
        or sys.argv[1].lower() != "scan"
    ):

        console.print(
            "[yellow]Usage:[/yellow]"
        )

        console.print(
            "  python main.py scan <target>"
        )

        console.print(
            "  python main.py scan <target> --quick"
        )

        console.print(
            "  python main.py scan <target> --normal"
        )

        console.print(
            "  python main.py scan <target> --full"
        )

        return

    # -----------------------------------------------------
    # TARGET
    # -----------------------------------------------------

    target = sys.argv[2]

    # -----------------------------------------------------
    # SCAN PROFILE
    # -----------------------------------------------------

    profile_arg = "--quick"

    if len(sys.argv) >= 4:

        profile_arg = (
            sys.argv[3]
            .lower()
        )

    if profile_arg == "--quick":

        host_limit = 25
        scan_profile = "quick"

    elif profile_arg == "--normal":

        host_limit = 250
        scan_profile = "normal"

    elif profile_arg == "--full":

        host_limit = None
        scan_profile = "full"

    else:

        console.print(
            f"[red]Unknown scan profile: "
            f"{profile_arg}[/red]"
        )

        console.print(
            "[yellow]Valid profiles: "
            "--quick, --normal, --full[/yellow]"
        )

        return

    # -----------------------------------------------------
    # SCAN INFORMATION
    # -----------------------------------------------------

    console.print()

    console.print(
        f"[bold]Target:[/bold] {target}"
    )

    console.print(
        f"[bold]Scan Profile:[/bold] "
        f"--{scan_profile}"
    )

    if host_limit is None:

        console.print(
            "[bold]Host Limit:[/bold] Unlimited"
        )

    else:

        console.print(
            f"[bold]Host Limit:[/bold] {host_limit}"
        )

    console.print()

    # -----------------------------------------------------
    # RECON
    # -----------------------------------------------------

    console.print(
        "[cyan]Starting reconnaissance...[/cyan]"
    )

    recon = ReconAgent()

    try:

        result = recon.scan(
            target,
            host_limit=host_limit
        )

    except KeyboardInterrupt:

        console.print(
            "\n[yellow]Scan cancelled by user.[/yellow]"
        )

        return

    except Exception as e:

        console.print(
            f"[red]Reconnaissance failed: "
            f"{type(e).__name__}: {e}[/red]"
        )

        return

    # -----------------------------------------------------
    # DISPLAY RECON
    # -----------------------------------------------------

    display_scan_result(
        result
    )

    # -----------------------------------------------------
    # BUILD TARGET PROFILE
    # -----------------------------------------------------

    console.print(
        "[cyan]Building target profile...[/cyan]"
    )

    try:

        target_profile = manager.build_profile(
            result
        )

    except Exception as e:

        console.print(
            f"[red]Target profiling failed: "
            f"{type(e).__name__}: {e}[/red]"
        )

        return

    display_target_profile(
        target_profile
    )

    # -----------------------------------------------------
    # CREATE AGENT PLAN
    # -----------------------------------------------------

    console.print(
        "[cyan]Creating agent execution plan...[/cyan]"
    )

    try:

        plan = manager.create_scan_plan(
            target_profile
        )

    except Exception as e:

        console.print(
            f"[red]Scan planning failed: "
            f"{type(e).__name__}: {e}[/red]"
        )

        return

    display_scan_plan(
        plan
    )

    # -----------------------------------------------------
    # EXECUTE MANAGER PLAN
    # -----------------------------------------------------

    console.print(
        "[cyan]Executing available agents...[/cyan]"
    )

    try:

        orchestration = manager.execute_scan_plan(
            profile=target_profile,
            scan_result=result
        )

    except Exception as e:

        console.print(
            f"[red]Agent orchestration failed: "
            f"{type(e).__name__}: {e}[/red]"
        )

        return

    display_execution(
        orchestration
    )

    # -----------------------------------------------------
    # SAVE BASE RECON REPORT
    # -----------------------------------------------------

    try:

        save_report(
            result
        )

    except Exception as e:

        console.print(
            f"[yellow]Report could not be saved: "
            f"{type(e).__name__}: {e}[/yellow]"
        )

    # -----------------------------------------------------
    # OPTIONAL AI ANALYSIS
    # -----------------------------------------------------

    run_ai_analysis(
        orchestration
    )

    # -----------------------------------------------------
    # COMPLETE
    # -----------------------------------------------------

    console.print(
        "[bold green]✓ BugHunter-ADK scan complete.[/bold green]"
    )


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    main()

