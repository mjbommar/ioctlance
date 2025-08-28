"""Progress tracking for batch analysis."""

from abc import ABC, abstractmethod
from pathlib import Path
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
)
from rich.table import Table
from rich.panel import Panel


class ProgressTracker(ABC):
    """Abstract base class for progress tracking."""

    @abstractmethod
    def start(self, total: int, description: str = "Processing...") -> None:
        """Start tracking progress."""
        pass

    @abstractmethod
    def update(self, advance: int = 1, description: str | None = None) -> None:
        """Update progress."""
        pass

    @abstractmethod
    def log(self, message: str, level: str = "info") -> None:
        """Log a message."""
        pass

    @abstractmethod
    def finish(self) -> None:
        """Finish tracking."""
        pass


class ConsoleProgressTracker(ProgressTracker):
    """Rich console progress tracker."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self.progress = None
        self.task = None
        self._context = None

    def start(self, total: int, description: str = "Processing...") -> None:
        """Start progress tracking with Rich."""
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            expand=False,
        )
        self._context = self.progress.__enter__()
        self.task = self.progress.add_task(f"[cyan]{description}", total=total)

    def update(self, advance: int = 1, description: str | None = None) -> None:
        """Update progress bar."""
        if self.progress and self.task is not None:
            if description:
                self.progress.update(self.task, description=f"[cyan]{description}")
            self.progress.advance(self.task, advance)

    def log(self, message: str, level: str = "info") -> None:
        """Log a message with appropriate styling."""
        if self.progress:
            style_map = {
                "error": "[red]✗[/red]",
                "warning": "[yellow]⚠[/yellow]",
                "success": "[green]✓[/green]",
                "info": "[blue]ℹ[/blue]",
            }
            prefix = style_map.get(level, "")
            if self.progress.console:
                self.progress.console.print(f"{prefix} {message}")
        else:
            self.console.print(message)

    def finish(self) -> None:
        """Clean up progress display."""
        if self._context:
            self.progress.__exit__(None, None, None)
            self._context = None

    def show_summary(self, stats: dict, vulnerable_drivers: list[tuple[str, int]] | None = None) -> None:
        """Show analysis summary table."""
        # Summary table
        summary_table = Table(title="Analysis Summary", show_header=True, header_style="bold magenta")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", justify="right")

        summary_table.add_row("Total drivers found", str(stats.get("total_drivers", 0)))
        summary_table.add_row("Successfully analyzed", f"[green]{stats.get('analyzed', 0)}[/green]")

        failed = stats.get("failed", 0)
        summary_table.add_row("Failed", f"[red]{failed}[/red]" if failed > 0 else "0")

        with_vulns = stats.get("with_vulnerabilities", 0)
        summary_table.add_row(
            "Drivers with vulnerabilities", f"[bold red]{with_vulns}[/bold red]" if with_vulns > 0 else "0"
        )

        total_vulns = stats.get("total_vulnerabilities", 0)
        summary_table.add_row(
            "Total vulnerabilities found", f"[bold red]{total_vulns}[/bold red]" if total_vulns > 0 else "0"
        )

        summary_table.add_row("Total time", f"{stats.get('analysis_time', 0):.2f} seconds")
        summary_table.add_row("Average time per driver", f"{stats.get('average_time_per_driver', 0):.2f} seconds")

        self.console.print("\n")
        self.console.print(summary_table)

        # Top vulnerable drivers
        if vulnerable_drivers:
            vuln_table = Table(title="Top Vulnerable Drivers", show_header=True, header_style="bold red")
            vuln_table.add_column("Driver", style="yellow")
            vuln_table.add_column("Vulnerabilities", justify="center", style="red")

            for driver_name, vuln_count in sorted(vulnerable_drivers, key=lambda x: x[1], reverse=True)[:10]:
                vuln_table.add_row(driver_name, str(vuln_count))

            self.console.print("\n")
            self.console.print(vuln_table)


class SilentProgressTracker(ProgressTracker):
    """Silent progress tracker for non-interactive environments."""

    def __init__(self):
        self.total = 0
        self.current = 0

    def start(self, total: int, description: str = "Processing...") -> None:
        """Start tracking (silent)."""
        self.total = total
        self.current = 0
        print(f"[START] {description} ({total} items)")

    def update(self, advance: int = 1, description: str | None = None) -> None:
        """Update progress (silent)."""
        self.current += advance
        if description:
            print(f"[{self.current}/{self.total}] {description}")

    def log(self, message: str, level: str = "info") -> None:
        """Log a message."""
        print(f"[{level.upper()}] {message}")

    def finish(self) -> None:
        """Finish tracking."""
        print(f"[COMPLETE] Processed {self.current}/{self.total} items")
