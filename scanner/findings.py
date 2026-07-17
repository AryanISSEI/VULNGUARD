"""Data models for vulnerability findings and patches."""
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(Enum):
    HIGH = "high"      # >90% sure, auto-suggest
    MEDIUM = "medium"  # 70-90%, recommend
    LOW = "low"        # <70%, flag for review


@dataclass
class CodeLocation:
    file: Path
    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0

    def to_sarif(self) -> Dict[str, Any]:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": str(self.file)},
                "region": {
                    "startLine": self.line_start,
                    "endLine": self.line_end,
                    "startColumn": self.column_start,
                    "endColumn": self.column_end,
                }
            }
        }


@dataclass
class Patch:
    """An auto-generated fix for a vulnerability."""
    original_code: str
    fixed_code: str
    description: str
    confidence: Confidence
    explanation: str  # Why this fix works

    def to_unified_diff(self, file_path: Path, finding_id: str) -> str:
        """Generate unified diff format for GitHub."""
        import difflib

        original_lines = self.original_code.splitlines(keepends=True)
        fixed_lines = self.fixed_code.splitlines(keepends=True)

        # Ensure lines end with newline for clean diff
        if original_lines and not original_lines[-1].endswith('\n'):
            original_lines[-1] += '\n'
        if fixed_lines and not fixed_lines[-1].endswith('\n'):
            fixed_lines[-1] += '\n'

        diff = difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm=''
        )

        return ''.join(diff)


@dataclass
class Finding:
    """A single vulnerability finding with fix."""
    id: str
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: Confidence
    message: str  # Plain English explanation
    location: CodeLocation
    snippet: str  # Vulnerable code
    patch: Optional[Patch] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_sarif(self) -> Dict[str, Any]:
        """Convert to SARIF format for GitHub integration."""
        result = {
            "ruleId": self.rule_id,
            "ruleIndex": 0,
            "level": self._sarif_level(),
            "message": {"text": self.message},
            "locations": [self.location.to_sarif()],
            "partialFingerprints": {
                "primaryLocationLineHash": hash(f"{self.location.file}:{self.location.line_start}")
            }
        }

        # Add fix suggestion if available
        if self.patch:
            result["fixes"] = [{
                "description": {"text": self.patch.description},
                "artifactChanges": [{
                    "artifactLocation": {"uri": str(self.location.file)},
                    "replacements": [{
                        "deletedRegion": self.location.to_sarif()["physicalLocation"]["region"],
                        "insertedContent": {"text": self.patch.fixed_code}
                    }]
                }]
            }]

        return result

    def _sarif_level(self) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note"
        }
        return mapping.get(self.severity, "warning")

    def to_pr_comment(self) -> str:
        """Generate GitHub PR comment markdown."""
        severity_emoji = {
            Severity.CRITICAL: "🚨",
            Severity.HIGH: "🔴",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢"
        }.get(self.severity, "⚪")

        lines = [
            f"{severity_emoji} **{self.rule_name}** ({self.severity.value})",
            "",
            self.message,
            "",
            f"**Location:** `{self.location.file}:{self.location.line_start}`",
            "",
            "**Vulnerable code:**",
            f"```python\n{self.snippet}\n```",
        ]

        if self.patch:
            lines.extend([
                "",
                f"**Suggested fix** (confidence: {self.patch.confidence.value}):",
                f"```python\n{self.patch.fixed_code}\n```",
                "",
                f"*Why this works:* {self.patch.explanation}"
            ])

        return "\n".join(lines)


@dataclass
class ScanResult:
    """Complete scan results."""
    findings: List[Finding]
    duration_ms: int
    files_scanned: int

    def to_sarif(self) -> Dict[str, Any]:
        """Generate full SARIF report."""
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Fix-First Scanner",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/your-org/vuln-scanner",
                        "rules": self._collect_rules()
                    }
                },
                "results": [f.to_sarif() for f in self.findings],
                "properties": {
                    "durationMs": self.duration_ms,
                    "filesScanned": self.files_scanned
                }
            }]
        }

    def _collect_rules(self) -> List[Dict[str, Any]]:
        """Extract unique rules from findings."""
        rules = {}
        for finding in self.findings:
            if finding.rule_id not in rules:
                rules[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.rule_name,
                    "defaultConfiguration": {
                        "level": finding._sarif_level()
                    }
                }
        return list(rules.values())

    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def patches_available(self) -> int:
        return sum(1 for f in self.findings if f.patch is not None)
