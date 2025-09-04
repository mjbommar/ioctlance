"""Rich-backed progress reporting for batch runs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    MofNCompleteColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table


class ProgressTracker(ABC):
    @abstractmethod
    def start(self, total: int, description: str = "Processing...") -> None: ...

    @abstractmethod
    def update(self, advance: int = 1, description: str | None = None) -> None: ...

    @abstractmethod
    def log(self, message: str, level: str = "info") -> None: ...

    @abstractmethod
    def finish(self) -> None: ...

    def show_summary(self, stats: dict, vulnerable: list[tuple[str, int]] | None = None) -> None: ...


class ConsoleProgressTracker(ProgressTracker):
    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self._progress: Progress | None = None
        self._task_id: int | None = None
        self._ctx = None

    def start(self, total: int, description: str = "Processing...") -> None:
        self._progress = Progress(
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
        self._ctx = self._progress.__enter__()
        self._task_id = self._progress.add_task(f"[cyan]{description}", total=total)

    def update(self, advance: int = 1, description: str | None = None) -> None:
        if not self._progress or self._task_id is None:
            return
        if description:
            self._progress.update(self._task_id, description=f"[cyan]{description}")
        self._progress.advance(self._task_id, advance)

    def log(self, message: str, level: str = "info") -> None:
        style = {
            "error": "[red]✗[/red]",
            "warning": "[yellow]⚠[/yellow]",
            "success": "[green]✓[/green]",
            "info": "[blue]ℹ[/blue]",
        }.get(level, "")
        if self._progress and self._progress.console:
            self._progress.console.print(f"{style} {message}")
        else:
            self.console.print(message)

    def finish(self) -> None:
        if self._ctx:
            assert self._progress is not None
            self._progress.__exit__(None, None, None)
            self._ctx = None

    def show_summary(self, stats: dict, vulnerable: list[tuple[str, int]] | None = None) -> None:
        table = Table(title="Analysis Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")
        table.add_row("Total drivers found", str(stats.get("total_drivers", 0)))
        table.add_row("Successfully analyzed", f"[green]{stats.get('analyzed', 0)}[/green]")
        failed = stats.get("failed", 0)
        table.add_row("Failed", f"[red]{failed}[/red]" if failed else "0")
        vulns = stats.get("total_vulnerabilities", 0)
        with_v = stats.get("with_vulnerabilities", 0)
        table.add_row("Drivers with vulnerabilities", f"[bold red]{with_v}[/bold red]" if with_v else "0")
        table.add_row("Total vulnerabilities found", f"[bold red]{vulns}[/bold red]" if vulns else "0")
        table.add_row("Total time", f"{stats.get('analysis_time', 0):.2f} seconds")
        table.add_row("Average time per driver", f"{stats.get('average_time_per_driver', 0):.2f} seconds")
        self.console.print("\n")
        self.console.print(table)
