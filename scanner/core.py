"""Core scanner engine that orchestrates detection rules."""
import time
from pathlib import Path
from typing import List, Optional, Set
import json

from scanner.findings import ScanResult, Finding
from scanner.rules import RULES


class Scanner:
    """Fix-First Vulnerability Scanner."""

    def __init__(self, fail_on: str = "high", include_paths: Optional[List[str]] = None):
        """
        Initialize scanner.

        Args:
            fail_on: Minimum severity to fail build ('critical', 'high', 'medium', 'low', 'none')
            include_paths: Specific paths to scan (default: auto-detect)
        """
        self.fail_on = fail_on
        self.include_paths = include_paths or []
        self.rules = [rule() for rule in RULES]

        # File extensions to scan
        self.SCAN_EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.html', '.htm', '.css', '.java', '.go'}
        self.IGNORE_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', '.claude'}

    def scan(self, target_path: Optional[Path] = None) -> ScanResult:
        """
        Run security scan on target directory.

        Args:
            target_path: Path to scan (default: current directory)

        Returns:
            ScanResult with findings and metadata
        """
        start_time = time.time()
        target = target_path or Path.cwd()

        # Collect files to scan
        files_to_scan = self._collect_files(target)

        # Run rules on each file
        all_findings: List[Finding] = []

        for file_path in files_to_scan:
            findings = self._scan_file(file_path)
            all_findings.extend(findings)

        # Sort by severity (critical first)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        all_findings.sort(key=lambda f: severity_order.get(f.severity.value, 99))

        duration_ms = int((time.time() - start_time) * 1000)

        return ScanResult(
            findings=all_findings,
            duration_ms=duration_ms,
            files_scanned=len(files_to_scan)
        )

    def _collect_files(self, target: Path) -> List[Path]:
        """Collect all files to scan."""
        files = []

        if target.is_file():
            return [target] if target.suffix in self.SCAN_EXTENSIONS else []

        for path in target.rglob('*'):
            # Skip ignored directories
            if any(ignored in path.parts for ignored in self.IGNORE_DIRS):
                continue

            if path.is_file() and path.suffix in self.SCAN_EXTENSIONS:
                files.append(path)

        return files

    def _scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file with all rules."""
        findings = []

        try:
            source = file_path.read_text(encoding='utf-8', errors='ignore')
        except IOError:
            return findings

        # Use HTML/CSS scanner for those file types
        if file_path.suffix in ['.html', '.htm', '.css']:
            from scanner.web_scanner import HTMLFileScanner
            html_scanner = HTMLFileScanner()

            if file_path.suffix in ['.html', '.htm']:
                web_findings = html_scanner.scan_html_file(str(file_path), source)
            elif file_path.suffix == '.css':
                web_findings = html_scanner.scan_css_file(str(file_path), source)
            else:
                web_findings = html_scanner.scan_js_file(str(file_path), source)

            # Convert WebFinding to Finding
            for wf in web_findings:
                from scanner.findings import Finding as CoreFinding, CodeLocation, Severity, Confidence
                severity_map = {
                    'critical': Severity.CRITICAL,
                    'high': Severity.HIGH,
                    'medium': Severity.MEDIUM,
                    'low': Severity.LOW,
                    'info': Severity.LOW
                }
                findings.append(CoreFinding(
                    id=wf.id,
                    rule_id=wf.rule_id,
                    rule_name=wf.rule_name,
                    severity=severity_map.get(wf.severity, Severity.LOW),
                    confidence=Confidence.HIGH if wf.confidence == 'high' else Confidence.MEDIUM,
                    message=wf.message,
                    location=CodeLocation(
                        file=file_path,
                        line_start=1,
                        line_end=1,
                        column_start=0,
                        column_end=len(wf.evidence) if isinstance(wf.evidence, str) else 100
                    ),
                    snippet=str(wf.evidence)[:200],
                    patch=None
                ))
            return findings

        # Regular code scanning
        for rule in self.rules:
            try:
                rule_findings = rule.analyze(file_path, source)
                findings.extend(rule_findings)
            except Exception as e:
                # Log error but continue scanning
                print(f"Error in {rule.__class__.__name__} for {file_path}: {e}")

        return findings

    def should_fail_build(self, result: ScanResult) -> bool:
        """Determine if scan should fail build based on severity threshold."""
        if self.fail_on == "none":
            return False

        severity_levels = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1
        }

        threshold = severity_levels.get(self.fail_on, 3)

        for finding in result.findings:
            finding_level = severity_levels.get(finding.severity.value, 0)
            if finding_level >= threshold:
                return True

        return False

    def generate_summary(self, result: ScanResult) -> str:
        """Generate human-readable scan summary."""
        lines = [
            "=" * 60,
            "  FIX-FIRST Security Scan Results",
            "=" * 60,
            "",
            f"  Files scanned: {result.files_scanned}",
            f"  Duration: {result.duration_ms}ms",
            "",
            "  VULNERABILITIES BY SEVERITY:",
            f"    Critical: {sum(1 for f in result.findings if f.severity.value == 'critical')}",
            f"    High:     {sum(1 for f in result.findings if f.severity.value == 'high')}",
            f"    Medium:   {sum(1 for f in result.findings if f.severity.value == 'medium')}",
            f"    Low:      {sum(1 for f in result.findings if f.severity.value == 'low')}",
            "",
            f"  Patches available: {result.patches_available()}",
            "",
        ]

        if result.findings:
            lines.extend([
                "  TOP FINDINGS:",
                ""
            ])
            for i, finding in enumerate(result.findings[:5], 1):
                lines.append(f"  {i}. [{finding.severity.value.upper()}] {finding.rule_name}")
                lines.append(f"     {finding.location.file}:{finding.location.line_start}")
                if finding.patch:
                    lines.append(f"     Fix available: {finding.patch.description}")
                lines.append("")

        if self.should_fail_build(result):
            lines.append("  RESULT: FAILED - Critical/High severity issues found")
        else:
            lines.append("  RESULT: PASSED")

        lines.extend(["", "=" * 60])

        return "\n".join(lines)

    def export_patches(self, result: ScanResult, output_dir: Path) -> None:
        """Export all patches as .diff files."""
        output_dir.mkdir(parents=True, exist_ok=True)

        for finding in result.findings:
            if finding.patch:
                patch_file = output_dir / f"{finding.id}.diff"
                diff = finding.patch.to_unified_diff(
                    finding.location.file,
                    finding.id
                )
                patch_file.write_text(diff)


class ScannerConfig:
    """Configuration for scanner runs."""

    def __init__(self, config_dict: Optional[dict] = None):
        self.fail_on = config_dict.get('fail_on', 'high') if config_dict else 'high'
        self.rules_enabled = config_dict.get('rules', ['sqli', 'xss', 'auth']) if config_dict else ['sqli', 'xss', 'auth']
        self.exclude_paths = config_dict.get('exclude', []) if config_dict else []
        self.include_paths = config_dict.get('include', []) if config_dict else []

    @classmethod
    def from_file(cls, path: Path) -> "ScannerConfig":
        """Load config from JSON file."""
        if not path.exists():
            return cls()

        try:
            with open(path) as f:
                return cls(json.load(f))
        except json.JSONDecodeError:
            return cls()
