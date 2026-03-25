"""
network_bot.main – CLI entry point for the autonomous network testing bot.
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich import box

from . import __version__
from .checks.base import CheckResult, Severity
from .checks import PortScanCheck, SSLCheck, HTTPCheck, DNSCheck, VulnCheck
from .config import load_config
from .reports.generator import ReportGenerator
from .scheduler import BotScheduler

console = Console()

BANNER = f"""[bold cyan]
 ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗    ██████╗  ██████╗ ████████╗
 ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝    ██╔══██╗██╔═══██╗╚══██╔══╝
 ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝     ██████╔╝██║   ██║   ██║   
 ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗     ██╔══██╗██║   ██║   ██║   
 ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗    ██████╔╝╚██████╔╝   ██║   
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═════╝  ╚═════╝    ╚═╝   
[/bold cyan]
[dim]  Autonomous Network Security Testing Bot  v{__version__}[/dim]
"""

CHECK_REGISTRY = {
    "port_scan": PortScanCheck,
    "ssl": SSLCheck,
    "http": HTTPCheck,
    "dns": DNSCheck,
    "vuln": VulnCheck,
}

SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "bold orange1",
    "medium": "bold yellow",
    "low": "green",
    "info": "blue",
}


def _configure_logging(level: str, log_file: Optional[str]) -> None:
    """Set up root logger with console and optional file handler."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    handlers: List[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        )
        handlers.append(file_handler)

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


class NetworkBot:
    """Core bot class that orchestrates checks and report generation."""

    def __init__(self, config: Dict[str, Any], targets: List[Dict[str, Any]]) -> None:
        self._config = config
        self._targets = targets
        self._reporter = ReportGenerator(config)

    def run_checks(self) -> List[CheckResult]:
        """Run all configured checks against all targets and generate a report."""
        all_results: List[CheckResult] = []
        timestamp = datetime.now(timezone.utc).isoformat()

        console.print(
            Panel(
                f"[bold]Starting scan of [cyan]{len(self._targets)}[/cyan] target(s)[/bold]",
                border_style="blue",
            )
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            total_checks = sum(len(t.get("checks", list(CHECK_REGISTRY.keys()))) for t in self._targets)
            overall_task = progress.add_task("[cyan]Overall progress", total=total_checks)

            for target in self._targets:
                host = target["host"]
                name = target.get("name", host)
                checks_to_run = target.get("checks", list(CHECK_REGISTRY.keys()))

                target_task = progress.add_task(
                    f"[yellow]{name} ({host})", total=len(checks_to_run)
                )

                for check_name in checks_to_run:
                    check_class = CHECK_REGISTRY.get(check_name)
                    if check_class is None:
                        logging.getLogger(__name__).warning(
                            "Unknown check '%s' for target '%s'", check_name, name
                        )
                        progress.advance(target_task)
                        progress.advance(overall_task)
                        continue

                    progress.update(
                        target_task,
                        description=f"[yellow]{name}[/yellow] → [white]{check_name}[/white]",
                    )

                    checker = check_class(self._config)
                    try:
                        result = checker.run(target)
                    except Exception as exc:
                        logging.getLogger(__name__).exception(
                            "Check '%s' crashed for target '%s': %s", check_name, name, exc
                        )
                        from .checks.base import CheckResult as CR
                        result = CR(
                            check_name=check_name,
                            target=host,
                            passed=False,
                            error=f"Unexpected error: {exc}",
                        )

                    all_results.append(result)
                    progress.advance(target_task)
                    progress.advance(overall_task)

                progress.remove_task(target_task)

        # Generate reports
        report_paths = self._reporter.generate(all_results, self._targets, timestamp)

        # Print summary
        self._print_summary(all_results, report_paths)

        return all_results

    def _print_summary(
        self, results: List[CheckResult], report_paths: Dict[str, Path]
    ) -> None:
        """Print a rich summary table to the console."""
        # Aggregate counts
        sev_counts = {s.value: 0 for s in Severity}
        pass_count = sum(1 for r in results if r.passed)
        fail_count = len(results) - pass_count

        for result in results:
            for finding in result.findings:
                sev_counts[finding.severity.value] += 1

        table = Table(title="Scan Summary", box=box.ROUNDED, border_style="blue")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        for sev_name, style in SEVERITY_STYLES.items():
            count = sev_counts.get(sev_name, 0)
            table.add_row(sev_name.upper(), f"[{style}]{count}[/{style}]")

        table.add_section()
        table.add_row("Checks Passed", f"[green]{pass_count}[/green]")
        table.add_row("Checks Failed", f"[red]{fail_count}[/red]")
        table.add_row("Total Findings", str(sum(sev_counts.values())))

        console.print(table)

        if report_paths:
            console.print("\n[bold]Reports generated:[/bold]")
            for fmt, path in report_paths.items():
                console.print(f"  [{fmt.upper()}] [link={path.resolve()}]{path.resolve()}[/link]")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-bot",
        description="Autonomous network security testing bot.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--config",
        metavar="CONFIG",
        default=None,
        help="Path to a YAML config file that overrides defaults.",
    )
    parser.add_argument(
        "--targets",
        metavar="TARGETS",
        default=None,
        help="Path to a YAML targets file.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run checks once and exit (do not start the scheduler).",
    )
    parser.add_argument(
        "--output",
        metavar="OUTPUT",
        default=None,
        help="Directory to write reports to (overrides config).",
    )
    parser.add_argument(
        "--format",
        dest="format",
        choices=["json", "html", "both"],
        default=None,
        help="Report format to generate (overrides config).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug-level logging.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Load config
    loaded = load_config(config_path=args.config, targets_path=args.targets)
    config: Dict[str, Any] = loaded["config"]
    targets: List[Dict[str, Any]] = loaded["targets"]

    # Apply CLI overrides
    log_level = "DEBUG" if args.verbose else config.get("logging", {}).get("level", "INFO")
    log_file = config.get("logging", {}).get("file")
    _configure_logging(log_level, log_file)

    if args.output:
        config.setdefault("reporting", {})["output_dir"] = args.output

    if args.format:
        formats = ["json", "html"] if args.format == "both" else [args.format]
        config.setdefault("reporting", {})["formats"] = formats

    # Print banner
    console.print(BANNER)

    if not targets:
        console.print(
            "[bold red]No targets configured.[/bold red] "
            "Create [cyan]config/targets.yaml[/cyan] from the example or use [cyan]--targets[/cyan]."
        )
        return 1

    console.print(
        f"[dim]Loaded [bold]{len(targets)}[/bold] target(s) | "
        f"Log level: [bold]{log_level}[/bold][/dim]\n"
    )

    bot = NetworkBot(config=config, targets=targets)

    if args.once:
        # Run once and exit
        bot.run_checks()
        return 0

    # Scheduled mode
    interval = config.get("scheduler", {}).get("interval_minutes", 60)
    scheduler_enabled = config.get("scheduler", {}).get("enabled", True)

    if not scheduler_enabled:
        console.print("[yellow]Scheduler disabled in config; running once.[/yellow]")
        bot.run_checks()
        return 0

    console.print(
        f"[bold green]Starting scheduler[/bold green] "
        f"(interval: [cyan]{interval} minute(s)[/cyan]). "
        "Press [bold]Ctrl+C[/bold] to stop.\n"
    )

    scheduler = BotScheduler(bot=bot, interval_minutes=interval)

    def _handle_shutdown(signum: int, frame: Any) -> None:
        console.print("\n[yellow]Shutdown signal received. Stopping...[/yellow]")
        scheduler.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    scheduler.start()

    # Block main thread
    try:
        while True:
            import time
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        scheduler.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
