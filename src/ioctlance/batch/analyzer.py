"""Redesigned batch analyzer orchestrating traversal, processing, and streaming output."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Iterable

from rich.console import Console

from .models import BatchConfig, BatchResult, DriverResult, AnalysisStats, ProcessingMode
from .progress import ConsoleProgressTracker, ProgressTracker
from .processor import parallel_process, sequential_process
from .stream import JSONLStreamer
from ..output.formats import OutputFormat

logger = logging.getLogger(__name__)


class BatchAnalyzer:
    """Batch analyzer for processing directories of drivers in parallel with streaming output."""

    def __init__(self, config: BatchConfig, console: Console | None = None):
        self.config = config
        self.console = console or Console()
        self.progress: ProgressTracker = (
            ConsoleProgressTracker(self.console)
            if config.show_progress
            else ConsoleProgressTracker(Console(record=True))
        )

        # State
        self.results: list[DriverResult] = []
        self.vulnerable_drivers: list[tuple[str, int]] = []
        self.failed_drivers: list[tuple[str, str]] = []
        self.clean_drivers: list[str] = []
        self._seen: set[str] = set()

        # Resume support
        self._load_resume_set()

    def _load_resume_set(self) -> None:
        src = self.config.resume_from
        if not src or not Path(src).exists():
            return
        try:
            if str(src).endswith(".jsonl"):
                with open(src, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            rec = json.loads(line)
                        except Exception:
                            continue
                        # Accept both legacy and summary shapes
                        if isinstance(rec, dict):
                            if rec.get("type") == "summary" and "driver" in rec:
                                self._seen.add(rec["driver"])
                            elif "driver_path" in rec:
                                self._seen.add(rec["driver_path"])
                            elif "driver" in rec:
                                self._seen.add(rec["driver"])
            else:
                with open(src, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and "results" in data:
                    for r in data["results"]:
                        d = r.get("driver") or r.get("driver_path")
                        if d:
                            self._seen.add(d)
        except Exception as e:
            logger.warning(f"Failed to load resume data from {src}: {e}")

        if self._seen:
            self.console.print(f"[yellow]↻[/yellow] Resuming: {len(self._seen)} drivers already analyzed")

    def _find_drivers(self, path: Path) -> list[Path]:
        if path.is_file():
            return [path] if path.suffix.lower() == ".sys" else []
        return list(path.rglob("*.sys")) if self.config.recursive_search else list(path.glob("*.sys"))

    def analyze_path(self, path: Path) -> BatchResult:
        self.console.print("[cyan]🔍 Scanning for driver files...[/cyan]")
        drivers = self._find_drivers(path)
        if not drivers:
            self.console.print("[red]No .sys files found[/red]")
            return BatchResult(stats=AnalysisStats(), results=[], config=self.config)

        # Filter by resume set
        if self._seen:
            drivers = [d for d in drivers if str(d) not in self._seen]
        if not drivers:
            self.console.print("[green]All drivers already analyzed[/green]")
            return BatchResult(stats=AnalysisStats(total_drivers=0), results=[], config=self.config)

        self.console.print(
            f"[green]✓[/green] Found [bold]{len(drivers)}[/bold] driver(s) to analyze (mode: {self.config.processing_mode.value})"
        )

        # Start streaming if JSONL
        streamer = JSONLStreamer(self.config) if self.config.output_format == OutputFormat.JSONL else None
        if streamer:
            # Announce destination early and record batch start
            try:
                self.console.print(f"[blue]Streaming JSONL to[/blue] {self.config.output_path}")
                streamer.write_event(
                    "batch_start",
                    path=str(self.config.output_path),
                    total=len(drivers),
                    search=self.config.search_strategy,
                    beam_width=self.config.beam_width,
                )
            except Exception as e:
                logger.warning(f"Failed to write batch_start record: {e}")

        # Start processing
        start = time.time()
        self.progress.start(len(drivers), "Analyzing drivers...")
        iterator = (
            parallel_process(self.config, drivers)
            if self.config.processing_mode == ProcessingMode.PARALLEL
            else sequential_process(self.config, drivers)
        )

        for res in iterator:
            self._consume_driver_result(res, streamer)
            self.progress.update(advance=1)

        self.progress.finish()

        # Finalize
        if streamer:
            try:
                streamer.write_event(
                    "batch_end",
                    path=str(self.config.output_path),
                    processed=len(self.results),
                    failed=len(self.failed_drivers),
                )
            finally:
                streamer.close()
        elapsed = time.time() - start
        stats = self._make_stats(elapsed)
        batch = BatchResult(stats=stats, results=self.results, config=self.config)

        # If JSON output requested, dump entire batch at end
        if self.config.output_format == OutputFormat.JSON:
            out = self.config.output_path
            with open(out, "w", encoding="utf-8") as f:
                data = {
                    **stats.model_dump(),
                    "results": [self._result_to_json(r) for r in self.results],
                }
                json.dump(data, f, indent=2, default=str)
            self.console.print(f"\n[green]Results saved to:[/green] {out}")
        else:
            self.console.print(f"\n[green]Results streamed to:[/green] {self.config.output_path}")

        # Summary output
        self._show_summary(stats)

        return batch

    def _consume_driver_result(self, result: DriverResult, streamer: JSONLStreamer | None) -> None:
        self.results.append(result)
        if result.success:
            if result.vuln_count > 0:
                self.vulnerable_drivers.append((result.filename, result.vuln_count))
            else:
                self.clean_drivers.append(result.filename)
        else:
            err = result.error[0] if result.error else "Unknown error"
            self.failed_drivers.append((result.filename, err))

        # Streaming JSONL per driver
        if streamer:
            if not self.config.filter_vulnerable or result.vuln_count > 0:
                streamer.write_driver_result(result)

    def _make_stats(self, total_time: float) -> AnalysisStats:
        total_vulns = sum(r.vuln_count for r in self.results)
        analyzed = len([r for r in self.results if r.success])
        return AnalysisStats(
            total_drivers=len(self.results),
            analyzed=analyzed,
            failed=len(self.failed_drivers),
            with_vulnerabilities=len(self.vulnerable_drivers),
            total_vulnerabilities=total_vulns,
            analysis_time=total_time,
            average_time_per_driver=(total_time / analyzed if analyzed else 0.0),
            workers_used=(self.config.num_workers),
        )

    def _show_summary(self, stats: AnalysisStats) -> None:
        if isinstance(self.progress, ConsoleProgressTracker):
            self.progress.show_summary(stats.model_dump(), self.vulnerable_drivers or None)

    @staticmethod
    def _result_to_json(r: DriverResult) -> dict:
        if isinstance(r.data, dict):
            data = r.data
        else:
            data = r.data.model_dump() if hasattr(r.data, "model_dump") else {}
        out = {
            "driver": str(r.driver_path),
            "success": r.success,
            "analysis_time": r.analysis_time,
            "vuln_count": r.vuln_count,
        }
        if data:
            out["analysis"] = data
        if r.error:
            out["error"] = r.error
        return out
