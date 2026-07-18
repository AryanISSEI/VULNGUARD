"""Tests for the vulnerability scanner."""
import pytest
from pathlib import Path

from scanner.core import Scanner
from scanner.rules.sqli import SQLInjectionRule
from scanner.rules.xss import XSSRule
from scanner.rules.auth import AuthRule


def get_fixture(name):
    return Path(__file__).parent / "fixtures" / name


class TestSQLInjectionRule:
    """Test SQL injection detection."""

    def test_finds_fstring_sql_injection(self):
        rule = SQLInjectionRule()
        fixture = get_fixture("vulnerable_api.py")
        findings = rule.analyze(fixture)

        # Should find at least 2 SQL injection vulnerabilities
        sqli_findings = [f for f in findings if "SQL Injection" in f.rule_name]
        assert len(sqli_findings) >= 2

        # Check specific vulnerable line
        line_numbers = [f.location.line_start for f in sqli_findings]
        assert 20 in line_numbers or 37 in line_numbers

    def test_generates_patch(self):
        rule = SQLInjectionRule()
        fixture = get_fixture("vulnerable_api.py")
        findings = rule.analyze(fixture)

        sqli_findings = [f for f in findings if "SQL Injection" in f.rule_name]

        # At least one finding should have a patch
        patched = [f for f in sqli_findings if f.patch is not None]
        assert len(patched) > 0

        # Patch should have required fields
        patch = patched[0].patch
        assert patch.fixed_code
        assert patch.description
        assert patch.explanation


class TestXSSRule:
    """Test XSS detection."""

    def test_finds_dangerously_set_inner_html(self):
        rule = XSSRule()
        fixture = get_fixture("vulnerable_components.jsx")
        findings = rule.analyze(fixture)

        xss_findings = [f for f in findings if "XSS" in f.rule_name]
        assert len(xss_findings) >= 3

        # Should find dangerouslySetInnerHTML
        danger_findings = [f for f in xss_findings if "dangerouslySetInnerHTML" in f.rule_name]
        assert len(danger_findings) >= 1

    def test_finds_eval_usage(self):
        rule = XSSRule()
        fixture = get_fixture("vulnerable_components.jsx")
        findings = rule.analyze(fixture)

        eval_findings = [f for f in findings if "eval" in f.rule_name.lower()]
        assert len(eval_findings) >= 1

        # Eval should be critical severity
        assert eval_findings[0].severity.value == "critical"


class TestAuthRule:
    """Test authentication issue detection."""

    def test_finds_hardcoded_secrets(self):
        rule = AuthRule()
        fixture = get_fixture("vulnerable_api.py")
        findings = rule.analyze(fixture)

        secret_findings = [f for f in findings if "Secret" in f.rule_name or "secret" in f.message.lower()]
        assert len(secret_findings) >= 1

    def test_finds_jwt_in_localstorage(self):
        rule = AuthRule()
        fixture = get_fixture("vulnerable_components.jsx")
        findings = rule.analyze(fixture)

        jwt_findings = [f for f in findings if "localStorage" in f.message or "JWT in" in f.rule_name]
        assert len(jwt_findings) >= 1


class TestScanner:
    """Test the core scanner."""

    def test_scan_directory(self):
        scanner = Scanner()
        result = scanner.scan(Path(__file__).parent / "fixtures")

        assert result.files_scanned > 0
        assert result.duration_ms >= 0
        assert len(result.findings) > 0

    def test_should_fail_build(self):
        scanner = Scanner(fail_on="high")
        fixture = get_fixture("vulnerable_api.py")
        result = scanner.scan(fixture)

        # Should fail on high severity
        assert scanner.should_fail_build(result)

    def test_generate_summary(self):
        scanner = Scanner()
        fixture = get_fixture("vulnerable_api.py")
        result = scanner.scan(fixture)

        summary = scanner.generate_summary(result)
        assert "Security Scan Results" in summary
        assert "findings" in summary.lower()

    def test_export_sarif(self, tmp_path):
        scanner = Scanner()
        fixture = get_fixture("vulnerable_api.py")
        result = scanner.scan(fixture)

        sarif = result.to_sarif()

        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) > 0

        # Check SARIF structure
        run = sarif["runs"][0]
        assert "tool" in run
        assert "results" in run


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
