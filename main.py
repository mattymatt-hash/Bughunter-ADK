import sys

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

    console.print("Connecting to Gemini...")

    manager = ManagerAgent()

    reply = manager.test_connection()

    console.print(f"[green]✓[/green] {reply}")


def display(result):

    console.print()

    console.print("[bold cyan]Scan Results[/bold cyan]")

    console.print(f"Target       : {result.target}")
    console.print(f"IP Address   : {result.ip}")
    console.print(f"HTTP Status  : {result.status}")
    console.print(f"Title        : {result.title}")
    console.print(f"Server       : {result.server}")
    console.print(f"Powered By   : {result.powered_by}")
    console.print(f"robots.txt   : {result.robots}")
    console.print(f"sitemap.xml  : {result.sitemap}")

    console.print()

    console.print("[bold cyan]Technologies[/bold cyan]")

    if result.technologies:

        for tech in result.technologies:
            console.print(f"✓ {tech}")

    else:

        console.print("None detected")

    console.print()

    console.print("[bold cyan]Discovered Hosts[/bold cyan]")

    count = len(result.hosts)

    console.print(f"Found {count} hosts")

    if count:

        for host in result.hosts[:25]:

            console.print(
                f"[green]{host.status:3}[/green]  {host.host}"
            )

            if host.technologies:

                console.print(
                    "      " + ", ".join(host.technologies[:4])
                )

        if count > 25:
            console.print(f"... and {count - 25} more")

    else:

        console.print("None found")


def main():

    banner()

    startup()

    if len(sys.argv) >= 3 and sys.argv[1] == "scan":

        target = sys.argv[2]

        recon = ReconAgent()

        result = recon.scan(target)

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