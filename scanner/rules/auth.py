"""Authentication/Authorization vulnerability detection."""
import re
from pathlib import Path
from typing import List, Optional, Dict, Any

from scanner.findings import Finding, Patch, Severity, Confidence, CodeLocation


class AuthRule:
    """Detect authentication misconfigurations in Python/FastAPI and JavaScript."""

    RULE_ID = "AUTH-001"
    RULE_NAME = "Authentication Issue"

    # JWT security issues
    JWT_ISSUES = {
        "HS256": {
            "severity": Severity.MEDIUM,
            "message": "JWT using HMAC-SHA256 - ensure secret key is strong",
            "recommendation": "Consider RS256 for asymmetric signing if applicable"
        },
        "none": {
            "severity": Severity.CRITICAL,
            "message": "JWT algorithm 'none' detected - signature disabled!",
            "recommendation": "Remove 'none' from allowed algorithms immediately"
        }
    }

    # Hardcoded secret patterns
    SECRET_PATTERNS = [
        (r'(SECRET_KEY|JWT_SECRET|API_KEY)\s*=\s*["\'][^"\']{8,}["\']\s*$',
         "Hardcoded secret in source code", Severity.HIGH),
        (r'password\s*=\s*["\'][^"\']+["\']\s*$',
         "Hardcoded password", Severity.CRITICAL),
        (r'Bearer\s+[a-zA-Z0-9_-]{20,}',
         "Hardcoded token", Severity.HIGH),
    ]

    # Session/cookie issues
    COOKIE_ISSUES = [
        (r'response\.set_cookie\s*\([^)]*\)',
         "Cookie without secure flags", Severity.MEDIUM),
    ]

    def __init__(self):
        pass

    def analyze(self, file_path: Path, source: Optional[str] = None) -> List[Finding]:
        """Analyze file for auth vulnerabilities."""
        findings = []

        if source is None:
            try:
                source = file_path.read_text(encoding='utf-8')
            except (UnicodeDecodeError, IOError):
                return findings

        # Check Python files (FastAPI)
        if file_path.suffix == '.py':
            findings.extend(self._analyze_python(source, file_path))

        # Check JavaScript files
        if file_path.suffix in ['.js', '.jsx', '.ts', '.tsx']:
            findings.extend(self._analyze_javascript(source, file_path))

        # Check Java/Go files
        # Check Java/Go files
        if file_path.suffix in ['.java', '.go']:
            findings.extend(self._analyze_java_go(source, file_path))

        # Config file checks
        findings.extend(self._analyze_config_files(source, file_path))

        return findings

    def _analyze_python(self, source: str, file_path: Path) -> List[Finding]:
        """Analyze Python code for auth issues."""
        findings = []
        lines = source.split('\n')

        for i, line in enumerate(lines, 1):
            # Check for hardcoded secrets
            findings.extend(self._check_secrets(line, i, file_path))

            # Check JWT configuration
            findings.extend(self._check_jwt_config(line, i, file_path, source))

            # Check cookie settings
            findings.extend(self._check_cookie_settings(line, i, file_path, source))

            # Check CORS misconfiguration
            findings.extend(self._check_cors(line, i, file_path, source))

        return findings

    def _analyze_javascript(self, source: str, file_path: Path) -> List[Finding]:
        """Analyze JavaScript code for auth issues."""
        findings = []
        lines = source.split('\n')

        for i, line in enumerate(lines, 1):
            # Check for hardcoded secrets
            findings.extend(self._check_secrets(line, i, file_path))

            # Check for JWT in localStorage (bad practice)
            findings.extend(self._check_jwt_storage(line, i, file_path))

            # Check for insecure auth patterns
            findings.extend(self._check_insecure_auth(line, i, file_path))

        return findings

    def _analyze_java_go(self, source: str, file_path: Path) -> List[Finding]:
        """Analyze Java/Go code for simple auth issues."""
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines, 1):
            # Check for hardcoded secrets
            findings.extend(self._check_secrets(line, i, file_path))
        return findings

    def _check_secrets(self, line: str, line_num: int, file_path: Path) -> List[Finding]:
        """Check for hardcoded secrets."""
        findings = []

        for pattern, desc, severity in self.SECRET_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                finding = Finding(
                    id=f"AUTH-SECRET-{file_path.stem}-{line_num}",
                    rule_id=self.RULE_ID,
                    rule_name="Hardcoded Secret",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    message=f"{desc}. Secrets should be in environment variables.",
                    location=CodeLocation(
                        file=file_path,
                        line_start=line_num,
                        line_end=line_num,
                        column_start=0,
                        column_end=len(line)
                    ),
                    snippet=line.strip(),
                    patch=self._generate_secret_fix(line, desc)
                )
                findings.append(finding)

        return findings

    def _check_jwt_config(self, line: str, line_num: int, file_path: Path,
                          full_source: str) -> List[Finding]:
        """Check FastAPI JWT configuration."""
        findings = []

        # Check for algorithm specification
        if re.search(r'algorithms?\s*=\s*\[', line):
            # Look for 'none' in algorithms list
            if "'none'" in line or '"none"' in line:
                finding = Finding(
                    id=f"AUTH-JWT-NONE-{line_num}",
                    rule_id=self.RULE_ID,
                    rule_name="JWT Algorithm None",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    message="JWT accepts 'none' algorithm - signature validation disabled!",
                    location=CodeLocation(
                        file=file_path,
                        line_start=line_num,
                        line_end=line_num,
                        column_start=0,
                        column_end=len(line)
                    ),
                    snippet=line.strip(),
                    patch=Patch(
                        original_code=line.strip(),
                        fixed_code=line.replace("'none'", "").replace('"none"', ""),
                        description="Remove 'none' from allowed algorithms",
                        confidence=Confidence.HIGH,
                        explanation="The 'none' algorithm disables signature verification, "
                                   "allowing anyone to forge tokens."
                    )
                )
                findings.append(finding)

        # Check for weak secrets
        if 'JWT_SECRET' in line or 'SECRET_KEY' in line:
            # Check if using a weak/default value
            if any(weak in line.lower() for weak in ['secret', 'password', 'key', 'default', 'test']):
                finding = Finding(
                    id=f"AUTH-JWT-WEAK-{line_num}",
                    rule_id=self.RULE_ID,
                    rule_name="Weak JWT Secret",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    message="JWT secret may be weak or default",
                    location=CodeLocation(
                        file=file_path,
                        line_start=line_num,
                        line_end=line_num,
                        column_start=0,
                        column_end=len(line)
                    ),
                    snippet=line.strip(),
                    patch=Patch(
                        original_code=line.strip(),
                        fixed_code="# Use: JWT_SECRET = os.environ['JWT_SECRET']",
                        description="Load JWT secret from environment variable",
                        confidence=Confidence.HIGH,
                        explanation="Secrets should be loaded from environment variables "
                                   "and be cryptographically strong (256+ bits)."
                    )
                )
                findings.append(finding)

        return findings

    def _check_cookie_settings(self, line: str, line_num: int, file_path: Path,
                               full_source: str) -> List[Finding]:
        """Check for secure cookie settings."""
        findings = []

        if 'set_cookie' in line:
            context_start = max(0, line_num - 5)
            context = '\n'.join(full_source.split('\n')[context_start:line_num])

            issues = []
            if 'secure' not in context.lower():
                issues.append("missing Secure flag")
            if 'httponly' not in context.lower():
                issues.append("missing HttpOnly flag")
            if 'samesite' not in context.lower():
                issues.append("missing SameSite attribute")

            if issues:
                finding = Finding(
                    id=f"AUTH-COOKIE-{file_path.stem}-{line_num}",
                    rule_id=self.RULE_ID,
                    rule_name="Insecure Cookie",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    message=f"Cookie {', '.join(issues)}",
                    location=CodeLocation(
                        file=file_path,
                        line_start=line_num,
                        line_end=line_num,
                        column_start=0,
                        column_end=len(line)
                    ),
                    snippet=line.strip(),
                    patch=Patch(
                        original_code=line.strip(),
                        fixed_code="# Add secure=True, httponly=True, samesite='Lax' to set_cookie()",
                        description="Add security flags to cookie",
                        confidence=Confidence.HIGH,
                        explanation="Secure flag requires HTTPS. HttpOnly prevents XSS from "
                                   "stealing cookies. SameSite mitigates CSRF."
                    )
                )
                findings.append(finding)

        return findings

    def _check_cors(self, line: str, line_num: int, file_path: Path,
                    full_source: str) -> List[Finding]:
        """Check for dangerous CORS configuration."""
        findings = []

        if 'CORSMiddleware' in line or 'allow_origins' in line:
            context_start = max(0, line_num - 10)
            context = '\n'.join(full_source.split('\n')[context_start:line_num + 5])

            # Check for allow_origins = ["*"]
            if re.search(r'allow_origins\s*=\s*\[["\']?\*["\']?\]', context):
                finding = Finding(
                    id=f"AUTH-CORS-{file_path.stem}-{line_num}",
                    rule_id=self.RULE_ID,
                    rule_name="Permissive CORS",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    message="CORS allows all origins ('*') - consider restricting to specific domains",
                    location=CodeLocation(
                        file=file_path,
                        line_start=line_num,
                        line_end=line_num,
                        column_start=0,
                        column_end=len(line)
                    ),
                    snippet=line.strip(),
                    patch=Patch(
                        original_code=line.strip(),
                        fixed_code='allow_origins=["https://yourdomain.com"]  # Restrict to specific origins',
                        description="Restrict CORS to specific origins",
                        confidence=Confidence.HIGH,
                        explanation="Wildcard CORS allows any website to make authenticated "
                                   "requests to your API. List specific trusted origins instead."
                    )
                )
                findings.append(finding)

        return findings

    def _check_jwt_storage(self, line: str, line_num: int, file_path: Path) -> List[Finding]:
        """Check for JWT stored in localStorage (vulnerable to XSS theft)."""
        findings = []

        if re.search(r'localStorage\.setItem\s*\(\s*["\']token', line) or \
           re.search(r'localStorage\.setItem\s*\(\s*["\']jwt', line):
            finding = Finding(
                id=f"AUTH-JWT-STORAGE-{line_num}",
                rule_id=self.RULE_ID,
                rule_name="JWT in localStorage",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                message="JWT stored in localStorage is vulnerable to XSS theft",
                location=CodeLocation(
                    file=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    column_start=0,
                    column_end=len(line)
                ),
                snippet=line.strip(),
                patch=Patch(
                    original_code=line.strip(),
                    fixed_code="// Use httpOnly cookies instead of localStorage\n// document.cookie = 'token=' + jwt + '; Secure; HttpOnly; SameSite=Strict';",
                    description="Store JWT in httpOnly cookie",
                    confidence=Confidence.HIGH,
                    explanation="localStorage is accessible to JavaScript, so XSS can steal tokens. "
                               "httpOnly cookies are inaccessible to JavaScript."
                )
            )
            findings.append(finding)

        return findings

    def _check_insecure_auth(self, line: str, line_num: int, file_path: Path) -> List[Finding]:
        """Check for insecure authentication patterns."""
        findings = []

        # Check for basic auth over HTTP
        if 'Authorization' in line and 'Basic' in line:
            finding = Finding(
                id=f"AUTH-BASIC-{line_num}",
                rule_id=self.RULE_ID,
                rule_name="HTTP Basic Auth",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                message="HTTP Basic Auth detected - ensure used over HTTPS only",
                location=CodeLocation(
                    file=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    column_start=0,
                    column_end=len(line)
                ),
                snippet=line.strip(),
                patch=None  # Context-dependent
            )
            findings.append(finding)

        return findings

    def _analyze_config_files(self, source: str, file_path: Path) -> List[Finding]:
        """Check configuration files (.env, config files)."""
        findings = []

        # .env file checks
        if file_path.name == '.env' or file_path.suffix == '.env':
            findings.extend(self._check_env_file(source, file_path))

        return findings

    def _check_env_file(self, source: str, file_path: Path) -> List[Finding]:
        """Check .env file for security issues."""
        findings = []
        lines = source.split('\n')

        for i, line in enumerate(lines, 1):
            # Check for default/example values
            if re.search(r'=(changeme|password|secret|default|admin|123456)', line, re.IGNORECASE):
                finding = Finding(
                    id=f"AUTH-ENV-{line_num}",
                    rule_id=self.RULE_ID,
                    rule_name="Weak Environment Value",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    message=f"Environment variable has weak/default value",
                    location=CodeLocation(
                        file=file_path,
                        line_start=i,
                        line_end=i,
                        column_start=0,
                        column_end=len(line)
                    ),
                    snippet=line.strip(),
                    patch=Patch(
                        original_code=line.strip(),
                        fixed_code="# TODO: Set strong secret here or in production environment",
                        description="Replace with strong random secret",
                        confidence=Confidence.HIGH,
                        explanation="Generate a strong secret: python -c \"import secrets; print(secrets.token_hex(32))\""
                    )
                )
                findings.append(finding)

        return findings

    def _generate_secret_fix(self, line: str, desc: str) -> Patch:
        """Generate fix for hardcoded secret."""
        # Extract variable name
        match = re.match(r'(\w+)\s*=', line)
        var_name = match.group(1) if match else "SECRET"

        return Patch(
            original_code=line.strip(),
            fixed_code=f"{var_name} = os.environ['{var_name}']  # Load from environment",
            description="Load secret from environment variable",
            confidence=Confidence.HIGH,
            explanation="Never commit secrets to version control. Use environment variables "
                       "loaded at runtime. Add the variable to your deployment environment."
        )
