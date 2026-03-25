"""
Network Testing Bot — autonomous network security scanner.

Usage:
  network-bot [--config CONFIG] [--targets TARGETS] [--once] [--output DIR] [--verbose]
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
from pathlib import Path
from typing import Dict, List

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .checks.base import CheckResult, Severity
from .checks.port_scan import PortScanCheck
from .checks.ssl_check import SSLCheck
from .checks.http_check import HTTPCheck
from .checks.dns_check import DNSCheck
from .checks.vuln_check import VulnCheck
from .config import load_config
from .reports.generator import generate_report
from .scheduler import BotScheduler

console = Console()

CHECK_REGISTRY = {
    "port_scan": PortScanCheck,
    "ssl": SSLCheck,
    "http": HTTPCheck,
    "dns": DNSCheck,
    "vuln": VulnCheck,
}

_SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def _setup_logging(verbose: bool, log_file: str | None = None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list = [RichHandler(console=console, rich_tracebacks=True, show_path=False)]

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path))

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
    )
    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def _print_banner() -> None:
    console.print(Panel.fit(
        f"[bold cyan]Network Testing Bot[/bold cyan] v{__version__}\n"
        "[dim]Autonomous network security scanner[/dim]",
        border_style="cyan",
    ))


def _print_summary_table(results_by_target: Dict[str, List[CheckResult]]) -> None:
    table = Table(title="Scan Summary", show_header=True, header_style="bold")
    table.add_column("Target", style="cyan")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Critical", justify="center", style="bold red")
    table.add_column("High", justify="center", style="red")
    table.add_column("Medium", justify="center", style="yellow")
    table.add_column("Low", justify="center", style="blue")
    table.add_column("Info", justify="center", style="dim")

    for host, results in results_by_target.items():
        for result in results:
            if result.error:
                table.add_row(host, result.check_name, "[red]ERROR[/red]", "-", "-", "-", "-", "-")
                continue
            counts = {s.value: 0 for s in Severity}
            for f in result.findings:
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
            status = "[green]PASS[/green]" if result.passed else "[red]FAIL[/red]"
            table.add_row(
                host,
                result.check_name,
                status,
                str(counts.get("critical", 0)) if counts.get("critical") else "[dim]0[/dim]",
                str(counts.get("high", 0)) if counts.get("high") else "[dim]0[/dim]",
                str(counts.get("medium", 0)) if counts.get("medium") else "[dim]0[/dim]",
                str(counts.get("low", 0)) if counts.get("low") else "[dim]0[/dim]",
                str(counts.get("info", 0)),
            )

    console.print(table)


class NetworkBot:
    """Main bot class that orchestrates checks and reporting."""

    def __init__(self, config: dict, targets: List[dict], output_dir: str = "reports"):
        self.config = config
        self.targets = targets
        self.output_dir = output_dir

    def run_checks(self) -> Dict[str, List[CheckResult]]:
        """Run all configured checks against all targets."""
        results_by_target: Dict[str, List[CheckResult]] = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            for target in self.targets:
                host = target["host"]
                name = target.get("name", host)
                requested_checks = target.get("checks", list(CHECK_REGISTRY.keys()))
                results: List[CheckResult] = []
                port_scan_metadata: dict = {}

                task = progress.add_task(f"Scanning [cyan]{name}[/cyan] ({host})", total=None)

                for check_name in requested_checks:
                    check_cls = CHECK_REGISTRY.get(check_name)
                    if check_cls is None:
                        logging.getLogger(__name__).warning(
                            "Unknown check '%s' — skipping", check_name
                        )
                        continue

                    progress.update(task, description=f"[cyan]{name}[/cyan] → {check_name}")

                    enriched_target = dict(target)
                    if check_name == "vuln" and port_scan_metadata:
                        enriched_target["_port_scan_banners"] = port_scan_metadata.get("banners", {})

                    try:
                        checker = check_cls(self.config)
                        result = checker.run(enriched_target)
                        results.append(result)

                        if check_name == "port_scan":
                            port_scan_metadata = result.metadata

                    except Exception as exc:
                        logging.getLogger(__name__).error(
                            "Check '%s' error for %s: %s", check_name, host, exc, exc_info=True
                        )
                        results.append(CheckResult(
                            check_name=check_name,
                            target=host,
                            passed=False,
                            error=str(exc),
                        ))

                results_by_target[host] = results
                progress.remove_task(task)

        _print_summary_table(results_by_target)

        reporting_cfg = self.config.get("reporting", {})
        formats = reporting_cfg.get("formats", ["json", "html"])
        written = generate_report(
            results_by_target=results_by_target,
            targets=self.targets,
            output_dir=self.output_dir,
            formats=formats,
        )

        for fmt, path in written.items():
            console.print(f"[green]Report saved:[/green] {path} ({fmt.upper()})")

        return results_by_target


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-bot",
        description="Autonomous network security testing bot",
    )
    parser.add_argument("--config", metavar="FILE", help="Path to config YAML override file")
    parser.add_argument("--targets", metavar="FILE", help="Path to targets YAML file")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run checks once and exit (default: run on schedule)",
    )
    parser.add_argument(
        "--output",
        metavar="DIR",
        default=None,
        help="Output directory for reports (default: from config, 'reports/')",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    return parser


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()

    # Load config
    cfg = load_config(config_path=args.config, targets_path=args.targets)
    config = cfg["config"]
    targets = cfg["targets"]

    # Setup logging
    log_file = config.get("logging", {}).get("file")
    _setup_logging(verbose=args.verbose, log_file=log_file)

    _print_banner()

    if not targets:
        console.print(
            "[yellow]No targets configured.[/yellow] "
            "Create [cyan]config/targets.yaml[/cyan] from the example file."
        )
        return 1

    console.print(f"Loaded [cyan]{len(targets)}[/cyan] target(s)")

    output_dir = args.output or config.get("reporting", {}).get("output_dir", "reports")
    bot = NetworkBot(config=config, targets=targets, output_dir=output_dir)

    if args.once:
        bot.run_checks()
        return 0

    # Scheduled mode
    scheduler = BotScheduler(bot=bot, interval_minutes=config.get("scheduler", {}).get("interval_minutes", 60))

    # Graceful shutdown on SIGINT/SIGTERM
    def _shutdown(signum, frame):
        console.print("\n[yellow]Shutting down...[/yellow]")
        scheduler.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    scheduler.start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
