"""
viridis.main – CLI entry point for the autonomous network testing bot.
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
from .alerting import AlertDispatcher
from .checks.base import CheckResult, Severity
from .checks import PortScanCheck, SSLCheck, HTTPCheck, DNSCheck, VulnCheck, SMTPCheck, ExposedPathsCheck, CipherCheck
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
    "smtp": SMTPCheck,
    "exposed_paths": ExposedPathsCheck,
    "cipher": CipherCheck,
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


class Viridis:
    """Core bot class that orchestrates checks and report generation."""

    def __init__(self, config: Dict[str, Any], targets: List[Dict[str, Any]]) -> None:
        self._config = config
        self._targets = targets
        self._reporter = ReportGenerator(config)
        self._alerter = AlertDispatcher(config)

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

        # Dispatch alerts
        self._alerter.dispatch(all_results, timestamp)

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
        prog="viridis",
        description="Autonomous network security testing bot. Starts the web GUI by default.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--config", metavar="FILE", default=None, help="YAML config override.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    # `serve` — default, starts the web GUI
    serve = subparsers.add_parser("serve", help="Start the web GUI (default)")
    serve.add_argument("--host", default="0.0.0.0", help="Bind host.")
    serve.add_argument("--port", type=int, default=8080, help="Bind port.")
    serve.add_argument("--targets", metavar="FILE", default=None, help="YAML targets to import on first run.")
    serve.add_argument("--reload", action="store_true", help="Auto-reload for development.")

    # `scan` — headless CLI scan
    scan = subparsers.add_parser("scan", help="Run scans from the CLI without the web GUI.")
    scan.add_argument("--targets", metavar="FILE", default=None, help="YAML targets file.")
    scan.add_argument("--target", metavar="HOST", default=None, help="Scan a single host (runs all checks).")
    scan.add_argument("--once", action="store_true", help="Run once and exit (skip scheduler).")
    scan.add_argument("--output", metavar="DIR", default=None, help="Report output directory.")
    scan.add_argument("--format", choices=["json", "html", "both"], default=None, help="Report format.")

    return parser


def _start_serve(args: argparse.Namespace, config: Dict[str, Any], targets: List[Dict[str, Any]]) -> int:
    import uvicorn
    from .web.app import create_app
    from .web.db.schema import init_db, get_db
    from .web.db.crud import get_targets as _get_targets, import_from_yaml

    db_path = config.get("web", {}).get("db_path", "data/viridis.db")
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    init_db(db_path)

    with get_db(db_path) as db:
        if not _get_targets(db) and targets:
            imported = import_from_yaml(db, targets)
            if imported:
                console.print(f"[green]Imported {imported} target(s) from YAML.[/green]")

    host = getattr(args, "host", None) or config.get("web", {}).get("host", "0.0.0.0")
    port = getattr(args, "port", None) or config.get("web", {}).get("port", 8080)
    reload = getattr(args, "reload", False)

    console.print(BANNER)
    console.print(f"[bold green]Web GUI[/bold green] → [cyan]http://{host}:{port}[/cyan]\n")
    uvicorn.run(create_app(config), host=host, port=port, reload=reload)
    return 0


def _start_scan(args: argparse.Namespace, config: Dict[str, Any], targets: List[Dict[str, Any]]) -> int:
    if getattr(args, "target", None):
        targets = [{"host": args.target, "name": args.target, "checks": list(CHECK_REGISTRY.keys())}]

    if getattr(args, "output", None):
        config.setdefault("reporting", {})["output_dir"] = args.output

    if getattr(args, "format", None):
        formats = ["json", "html"] if args.format == "both" else [args.format]
        config.setdefault("reporting", {})["formats"] = formats

    console.print(BANNER)

    if not targets:
        console.print(
            "[bold red]No targets.[/bold red] Use [cyan]--targets FILE[/cyan] or [cyan]--target HOST[/cyan]."
        )
        return 1

    console.print(f"[dim]{len(targets)} target(s) loaded.[/dim]\n")
    bot = Viridis(config=config, targets=targets)

    if getattr(args, "once", False):
        bot.run_checks()
        return 0

    interval = config.get("scheduler", {}).get("interval_minutes", 60)
    if not config.get("scheduler", {}).get("enabled", True):
        bot.run_checks()
        return 0

    console.print(f"[bold green]Scheduler[/bold green] running every [cyan]{interval}m[/cyan]. Ctrl+C to stop.\n")
    scheduler = BotScheduler(bot=bot, interval_minutes=interval)

    def _shutdown(signum: int, frame: Any) -> None:
        scheduler.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    scheduler.start()

    try:
        while True:
            import time
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        scheduler.stop()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    targets_path = getattr(args, "targets", None)
    loaded = load_config(config_path=args.config, targets_path=targets_path)
    config: Dict[str, Any] = loaded["config"]
    targets: List[Dict[str, Any]] = loaded["targets"]

    log_level = "DEBUG" if args.verbose else config.get("logging", {}).get("level", "INFO")
    _configure_logging(log_level, config.get("logging", {}).get("file"))

    # Default command is `serve`
    command = getattr(args, "command", None) or "serve"

    if command == "scan":
        return _start_scan(args, config, targets)
    return _start_serve(args, config, targets)


if __name__ == "__main__":
    sys.exit(main())
