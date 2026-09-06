import sys
from unittest import result

from rich.console import Console

from agents.manager.ai_analyzer import AIAnalyzer
from config.settings import APP_NAME
from database.database import init_database
from agents.manager.manager import ManagerAgent
from agents.recon.recon_agent import ReconAgent
from agents.recon.report_writer import ReportWriter

console = Console()


def banner():

    console.print("=" * 50, style="cyan")
    console.print(APP_NAME, style="bold green")
    console.print("=" * 50, style="cyan")


def startup():

    init_database()

    console.print("[green]✓[/green] SQLite database initialized")
    console.print()

    console.print("Connecting to Gemini...")

    manager = ManagerAgent()

    reply = manager.test_connection()

    if reply == "BugHunter ADK Online":

        console.print("[green]✓[/green] Gemini connected")

    elif reply == "Gemini unavailable":

        console.print("[yellow]⚠[/yellow] Gemini unavailable")
        console.print("Continuing in offline mode...")

    else:

        console.print(f"[yellow]⚠[/yellow] {reply}")

    console.print()


def display(result):

    console.print()

    console.print("[bold cyan]Scan Results[/bold cyan]")

    console.print(f"Target       : {result.target}")
    console.print(f"IP Address   : {result.ip}")
    console.print(f"HTTP Status  : {result.status}")
    console.print(f"Title        : {result.title}")
    console.print(f"Server       : {result.server}")
    console.print(f"Powered By   : {result.powered_by}")
    # -----------------------------------
    # robots.txt
    # -----------------------------------

    console.print()

    console.print("[bold cyan]robots.txt[/bold cyan]")

    if result.robots.found:

        console.print("[green]Found[/green]")

        console.print(
            f"Disallow Rules : {len(result.robots.disallow)}"
        )

        console.print(
            f"Allow Rules    : {len(result.robots.allow)}"
        )

        console.print(
            f"Sitemaps       : {len(result.robots.sitemaps)}"
        )

        console.print(
            f"Interesting    : {len(result.robots.interesting_paths)}"
        )

    else:

        console.print("Not Found")

        # -----------------------------------
        # sitemap.xml
        # -----------------------------------

        console.print()

        console.print("[bold cyan]sitemap.xml[/bold cyan]")

        if result.sitemap.found:

            console.print("[green]Found[/green]")

            console.print(
                f"URLs      : {len(result.sitemap.urls)}"
            )

            console.print(
                f"APIs      : {len(result.sitemap.apis)}"
            )

            console.print(
                f"Images    : {len(result.sitemap.images)}"
            )

            console.print(
                f"News      : {len(result.sitemap.news)}"
            )

            console.print(
                f"Languages : {len(result.sitemap.alternate_languages)}"
            )

        else:

            console.print("Not Found")

            console.print()

            console.print("[bold cyan]Technologies[/bold cyan]")

    if result.technologies:

        for tech in result.technologies:
            console.print(f"✓ {tech}")

    else:

        console.print("None detected")

    console.print()

    console.print("[bold cyan]Discovered Hosts[/bold cyan]")

    total_hosts = len(result.hosts)

    live_hosts = [h for h in result.hosts if h.status > 0]

    success = sum(1 for h in live_hosts if 200 <= h.status < 300)
    redirects = sum(1 for h in live_hosts if 300 <= h.status < 400)
    forbidden = sum(1 for h in live_hosts if h.status == 403)
    not_found = sum(1 for h in live_hosts if h.status == 404)
    server_errors = sum(1 for h in live_hosts if 500 <= h.status < 600)

    console.print(f"Found      : {total_hosts}")
    console.print(f"Live       : {len(live_hosts)}")
    console.print(f"2xx        : {success}")
    console.print(f"3xx        : {redirects}")
    console.print(f"403        : {forbidden}")
    console.print(f"404        : {not_found}")
    console.print(f"5xx        : {server_errors}")

    console.print()

    sorted_hosts = sorted(
        live_hosts,
        key=lambda h: (
            0 if 200 <= h.status < 300 else
            1 if 300 <= h.status < 400 else
            2 if h.status == 403 else
            3 if h.status == 404 else
            4 if h.status >= 500 else
            5,
            h.host.lower()
        )
    )

    for host in sorted_hosts[:30]:

        console.print(
            f"[green]{host.status:3}[/green]  {host.host}"
        )

        if host.technologies:

            console.print(
                "      " + ", ".join(host.technologies[:5])
            )

    if len(sorted_hosts) > 30:

        console.print(
            f"... and {len(sorted_hosts) - 30} more live hosts"
        )


def main():

    banner()

    startup()

    if len(sys.argv) < 3 or sys.argv[1] != "scan":

        console.print(
            "[red]Usage:[/red] python main.py scan <target> "
            "[--quick|--normal|--full]"
        )

        return

    target = sys.argv[2]

    profile = "--quick"

    if len(sys.argv) >= 4:
        profile = sys.argv[3].lower()

    if profile == "--quick":

        host_limit = 25

    elif profile == "--normal":

        host_limit = 250

    elif profile == "--full":

        host_limit = None

    else:

        console.print(
            "[red]Unknown scan profile.[/red]"
        )

        return

    console.print()
    console.print(f"[cyan]Scan Profile:[/cyan] {profile}")

    recon = ReconAgent()

    result = recon.scan(
        target,
        host_limit=host_limit
    )

    display(result)

    writer = ReportWriter()

    filename = writer.save(result)

    console.print()

    console.rule("[bold green]AI Security Assessment")

    analysis = AIAnalyzer().analyze(result)

    console.print(analysis)

    console.print()

    console.print(f"[green]✓ Report saved:[/green] {filename}")


if __name__ == "__main__":
    main()