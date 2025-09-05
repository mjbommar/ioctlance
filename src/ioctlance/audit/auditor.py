"""Core auditor for individual vulnerability analysis using Claude Code CLI."""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from enum import Enum
import logging

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AuditClassification(str, Enum):
    """Vulnerability audit classifications."""

    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    ERROR = "ERROR"


class AuditResult(BaseModel):
    """Result of a vulnerability audit."""

    classification: AuditClassification
    confidence: int = Field(ge=0, le=100)
    evidence: dict[str, Any] = Field(default_factory=dict)
    reasoning: str
    investigation_commands: list[str] = Field(default_factory=list)
    vulnerable_address: str | None = None
    ioctl_handler: str | None = None
    control_flow: str | None = None
    constraints: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True


class VulnerabilityAuditor:
    """Audits individual vulnerabilities using Claude Code CLI."""

    def __init__(self, claude_command: str = "npx @anthropic-ai/claude-code", verbose: bool = False):
        """
        Initialize the auditor.

        Args:
            claude_command: Path to Claude Code CLI command (default: npx @anthropic-ai/claude-code)
            verbose: Enable verbose output
        """
        self.claude_command = claude_command
        self.verbose = verbose

    def audit(self, driver_path: Path, vulnerability: dict[str, Any], timeout: int = 300) -> AuditResult:
        """
        Audit a single vulnerability.

        Args:
            driver_path: Path to the driver file
            vulnerability: Vulnerability details from IOCTLance
            timeout: Timeout in seconds for the audit

        Returns:
            AuditResult with classification and evidence
        """
        # Create investigation prompt
        prompt = self._create_investigation_prompt(driver_path, vulnerability)

        # Run Claude Code CLI
        try:
            result = self._run_claude(prompt, timeout)
            return self._parse_audit_result(result)
        except subprocess.TimeoutExpired:
            logger.error(f"Audit timed out for {driver_path}")
            return AuditResult(classification=AuditClassification.ERROR, confidence=0, reasoning="Audit timed out")
        except Exception as e:
            logger.error(f"Audit failed for {driver_path}: {e}")
            return AuditResult(
                classification=AuditClassification.ERROR, confidence=0, reasoning=f"Audit failed: {str(e)}"
            )

    def _create_investigation_prompt(self, driver_path: Path, vulnerability: dict[str, Any]) -> str:
        """Create the investigation prompt for Claude Code."""

        # Extract key vulnerability details
        title = vulnerability.get("title", "Unknown")
        ioctl = vulnerability.get("eval", {}).get("IoControlCode", "unknown")

        # Check if analysis JSON exists
        json_path = f"{driver_path}.json"

        prompt = f"""Audit this vulnerability using these tools:

1. First read the vulnerability details:
   cat {json_path} | jq '.vulnerabilities[] | select(.vulnerability.eval.IoControlCode == "{ioctl}")'

2. Check the binary with objdump:
   objdump -d {driver_path} | grep -A 50 "{ioctl}"

3. Look for the IOCTL handler:
   nm {driver_path} | grep -i dispatch

4. Check for vulnerable functions:
   strings {driver_path} | grep -E "(memcpy|strcpy|sprintf)"

Is the {title} at IOCTL {ioctl} exploitable?
Output: {{"classification": "TRUE_POSITIVE/FALSE_POSITIVE/NEEDS_REVIEW", "confidence": 0-100, "reasoning": "explain why"}}"""

        return prompt

    def _run_claude(self, prompt: str, timeout: int) -> str:
        """Run Claude Code CLI with the given prompt."""
        # Write prompt to temporary file (handles complex prompts better)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(prompt)
            prompt_file = f.name

        try:
            # Run Claude Code using npx (will auto-install if needed)
            # Split the command if it contains spaces (e.g., "npx @anthropic-ai/claude-code")
            cmd_parts = self.claude_command.split()
            cmd = cmd_parts + [
                "-p",
                f"@{prompt_file}",  # @ prefix to read from file
            ]

            if self.verbose:
                logger.info(f"Running: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            if result.returncode != 0:
                raise RuntimeError(f"Claude Code failed: {result.stderr}")

            return result.stdout

        finally:
            # Clean up temp file
            Path(prompt_file).unlink(missing_ok=True)

    def _parse_audit_result(self, claude_output: str) -> AuditResult:
        """Parse Claude Code output into AuditResult."""
        try:
            # Claude should output JSON, but may have other text
            # Try to extract JSON from the output
            import re

            # Look for JSON block
            json_match = re.search(r'\{.*"classification".*\}', claude_output, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                # Try parsing entire output as JSON
                data = json.loads(claude_output)

            # Map to AuditResult
            classification = data.get("classification", "ERROR")
            if classification not in [e.value for e in AuditClassification]:
                classification = AuditClassification.NEEDS_REVIEW
            else:
                classification = AuditClassification(classification)

            return AuditResult(
                classification=classification,
                confidence=data.get("confidence", 50),
                evidence=data.get("evidence", {}),
                reasoning=data.get("reasoning", "No reasoning provided"),
                investigation_commands=data.get("investigation_commands", []),
                vulnerable_address=data.get("evidence", {}).get("vulnerable_address"),
                ioctl_handler=data.get("evidence", {}).get("ioctl_handler"),
                control_flow=data.get("evidence", {}).get("control_flow"),
                constraints=data.get("constraints", []),
                mitigations=data.get("mitigations", []),
            )

        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse Claude output: {e}")
            logger.debug(f"Raw output: {claude_output}")

            # Try to extract some information even if parsing failed
            if "TRUE_POSITIVE" in claude_output:
                classification = AuditClassification.TRUE_POSITIVE
            elif "FALSE_POSITIVE" in claude_output:
                classification = AuditClassification.FALSE_POSITIVE
            else:
                classification = AuditClassification.NEEDS_REVIEW

            return AuditResult(
                classification=classification, confidence=25, reasoning=f"Partial parse: {claude_output[:500]}"
            )
