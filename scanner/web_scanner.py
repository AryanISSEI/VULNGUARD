"""Web vulnerability scanner for analyzing live websites."""
import asyncio
import ssl
import socket
import json
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict
import re


@dataclass
class WebFinding:
    """Finding from web scan."""
    id: str
    rule_id: str
    rule_name: str
    severity: str  # critical, high, medium, low, info
    confidence: str
    message: str
    url: str
    evidence: str
    remediation: str
    category: str


class WebSecurityScanner:
    """Scanner for live website vulnerabilities."""

    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'medium',
            'message': 'Missing HSTS header - site vulnerable to SSL stripping',
            'remediation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'message': 'Missing X-Frame-Options - site may be clickjacked',
            'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'severity': 'low',
            'message': 'Missing X-Content-Type-Options - MIME sniffing possible',
            'remediation': 'Add X-Content-Type-Options: nosniff'
        },
        'Referrer-Policy': {
            'severity': 'low',
            'message': 'Missing Referrer-Policy - may leak sensitive URLs',
            'remediation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Content-Security-Policy': {
            'severity': 'high',
            'message': 'Missing CSP - XSS protection limited',
            'remediation': 'Add Content-Security-Policy with strict directives'
        },
        'Permissions-Policy': {
            'severity': 'info',
            'message': 'Missing Permissions-Policy - features not restricted',
            'remediation': 'Add Permissions-Policy to restrict unused browser features'
        }
    }

    def __init__(self, timeout: int = 30, follow_redirects: bool = True):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.visited_urls: Set[str] = set()
        self.findings: List[WebFinding] = []

    async def scan_url(self, url: str, depth: int = 2) -> Dict[str, Any]:
        """Scan a single URL for vulnerabilities."""
        findings = []
        parsed = urlparse(url)

        if not parsed.scheme:
            url = f"https://{url}"
            parsed = urlparse(url)

        print(f"Scanning {url}...")

        # Run all checks
        try:
            # Try HTTPS first
            findings.extend(await self._check_https(url))
            findings.extend(await self._check_headers(url))
            findings.extend(await self._check_ssl_tls(url))

            # Fetch page content
            content, headers = await self._fetch_url(url)
            if content:
                findings.extend(self._check_content_security(url, content, headers))
                findings.extend(self._check_forms(url, content))
                findings.extend(await self._check_sensitive_files(url))
                findings.extend(self._check_cors_configuration(url, headers))

            # Check server info exposure
            findings.extend(self._check_server_exposure(headers))

        except Exception as e:
            findings.append(WebFinding(
                id=f"ERROR-{hash(url) % 10000}",
                rule_id="SCAN-001",
                rule_name="Scan Error",
                severity="info",
                confidence="high",
                message=f"Failed to scan: {str(e)}",
                url=url,
                evidence=str(e),
                remediation="Check if the site is accessible",
                category="scan"
            ))

        return {
            "url": url,
            "findings": [asdict(f) for f in findings],
            "summary": {
                "critical": len([f for f in findings if f.severity == "critical"]),
                "high": len([f for f in findings if f.severity == "high"]),
                "medium": len([f for f in findings if f.severity == "medium"]),
                "low": len([f for f in findings if f.severity == "low"]),
                "info": len([f for f in findings if f.severity == "info"]),
                "total": len(findings)
            }
        }

    async def _fetch_url(self, url: str) -> tuple:
        """Fetch URL and return content + headers."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,  # We'll check SSL separately
                    allow_redirects=self.follow_redirects
                ) as response:
                    content = await response.text()
                    headers = dict(response.headers)
                    return content, headers
        except ImportError:
            # Fallback to requests
            import requests
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=self.follow_redirects
            )
            return response.text, dict(response.headers)

    async def _check_https(self, url: str) -> List[WebFinding]:
        """Check if site enforces HTTPS."""
        findings = []
        parsed = urlparse(url)

        if parsed.scheme != 'https':
            findings.append(WebFinding(
                id=f"HTTPS-001-{hash(url) % 10000}",
                rule_id="HTTPS-001",
                rule_name="HTTPS Not Enforced",
                severity="high",
                confidence="high",
                message="Site does not use HTTPS - traffic is unencrypted",
                url=url,
                evidence=f"Scheme: {parsed.scheme}",
                remediation="Enable HTTPS and redirect HTTP to HTTPS",
                category="transport"
            ))

        return findings

    async def _check_headers(self, url: str) -> List[WebFinding]:
        """Check security headers."""
        findings = []
        _, headers = await self._fetch_url(url)
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, config in self.SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                findings.append(WebFinding(
                    id=f"HEADER-{header}-{hash(url) % 10000}",
                    rule_id=f"HEADER-{header}",
                    rule_name=f"Missing {header}",
                    severity=config['severity'],
                    confidence="high",
                    message=config['message'],
                    url=url,
                    evidence=f"Header not present in response",
                    remediation=config['remediation'],
                    category="headers"
                ))

        # Check for dangerous headers
        if 'x-powered-by' in headers_lower:
            findings.append(WebFinding(
                id=f"HEADER-LEAK-{hash(url) % 10000}",
                rule_id="HEADER-LEAK",
                rule_name="Information Disclosure",
                severity="low",
                confidence="high",
                message=f"X-Powered-By reveals technology: {headers_lower['x-powered-by']}",
                url=url,
                evidence=headers_lower['x-powered-by'],
                remediation="Remove X-Powered-By header from server configuration",
                category="headers"
            ))

        # Check for weak CSP
        if 'content-security-policy' in headers_lower:
            csp = headers_lower['content-security-policy']
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                findings.append(WebFinding(
                    id=f"CSP-WEAK-{hash(url) % 10000}",
                    rule_id="CSP-WEAK",
                    rule_name="Weak CSP Configuration",
                    severity="medium",
                    confidence="high",
                    message="CSP allows unsafe-inline or unsafe-eval",
                    url=url,
                    evidence=csp,
                    remediation="Remove 'unsafe-inline' and 'unsafe-eval' from CSP, use nonces or hashes",
                    category="headers"
                ))

        return findings

    async def _check_ssl_tls(self, url: str) -> List[WebFinding]:
        """Check SSL/TLS configuration."""
        findings = []
        parsed = urlparse(url)

        if parsed.scheme != 'https':
            return findings

        try:
            context = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check TLS version
                    if version in ['TLSv1', 'TLSv1.1']:
                        findings.append(WebFinding(
                            id=f"TLS-OLD-{hash(url) % 10000}",
                            rule_id="TLS-OLD",
                            rule_name="Outdated TLS Version",
                            severity="high",
                            confidence="high",
                            message=f"Using {version} - outdated and insecure",
                            url=url,
                            evidence=f"TLS version: {version}",
                            remediation="Disable TLS 1.0/1.1, enable TLS 1.2+ only",
                            category="ssl"
                        ))

                    # Check certificate expiry
                    cert = ssock.getpeercert()
                    if cert:
                        from datetime import datetime
                        not_after = cert.get('notAfter')
                        if not_after:
                            expiry = ssl.cert_time_to_seconds(not_after)
                            days_left = (expiry - datetime.now().timestamp()) / 86400
                            if days_left < 30:
                                findings.append(WebFinding(
                                    id=f"CERT-EXP-{hash(url) % 10000}",
                                    rule_id="CERT-EXP",
                                    rule_name="Certificate Expiring Soon",
                                    severity="medium",
                                    confidence="high",
                                    message=f"SSL certificate expires in {int(days_left)} days",
                                    url=url,
                                    evidence=f"Expiry: {not_after}",
                                    remediation="Renew SSL certificate",
                                    category="ssl"
                                ))

        except Exception as e:
            findings.append(WebFinding(
                id=f"SSL-ERR-{hash(url) % 10000}",
                rule_id="SSL-ERR",
                rule_name="SSL/TLS Error",
                severity="high",
                confidence="medium",
                message=f"SSL/TLS connection issue: {str(e)}",
                url=url,
                evidence=str(e)[:100],
                remediation="Check SSL certificate configuration",
                category="ssl"
            ))

        return findings

    def _check_content_security(self, url: str, content: str, headers: dict) -> List[WebFinding]:
        """Check content for security issues."""
        findings = []

        # Check for mixed content (HTTP resources on HTTPS page)
        parsed = urlparse(url)
        if parsed.scheme == 'https':
            http_resources = re.findall(r'http://[^\s"\'<>]+', content)
            if http_resources:
                findings.append(WebFinding(
                    id=f"MIXED-{hash(url) % 10000}",
                    rule_id="MIXED-CONTENT",
                    rule_name="Mixed Content",
                    severity="medium",
                    confidence="high",
                    message=f"HTTPS page loads {len(http_resources)} HTTP resources",
                    url=url,
                    evidence=http_resources[:3],
                    remediation="Load all resources over HTTPS",
                    category="content"
                ))

        # Check for inline scripts
        inline_scripts = re.findall(r'<script[^>]*>[^<]*</script>', content, re.IGNORECASE)
        if len(inline_scripts) > 0:
            findings.append(WebFinding(
                id=f"SCRIPT-INLINE-{hash(url) % 10000}",
                rule_id="SCRIPT-INLINE",
                rule_name="Inline JavaScript",
                severity="low",
                confidence="medium",
                message=f"Found {len(inline_scripts)} inline script blocks",
                url=url,
                evidence="<script>...</script> blocks present",
                remediation="Move JavaScript to external files, use CSP nonces if inline required",
                category="content"
            ))

        # Check for inline styles
        inline_styles = re.findall(r'style\s*=\s*["\'][^"\']*["\']', content, re.IGNORECASE)
        if len(inline_styles) > 5:  # Threshold
            findings.append(WebFinding(
                id=f"STYLE-INLINE-{hash(url) % 10000}",
                rule_id="STYLE-INLINE",
                rule_name="Excessive Inline Styles",
                severity="info",
                confidence="low",
                message=f"Found {len(inline_styles)} inline style attributes",
                url=url,
                evidence="style=\"...\" attributes present",
                remediation="Move styles to external CSS files",
                category="content"
            ))

        # Check for comments containing sensitive info
        comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
        sensitive_patterns = ['password', 'secret', 'key', 'token', 'admin', 'todo', 'fixme', 'hack']
        for comment in comments:
            for pattern in sensitive_patterns:
                if pattern in comment.lower():
                    findings.append(WebFinding(
                        id=f"COMMENT-SENSITIVE-{hash(url) % 10000}",
                        rule_id="COMMENT-SENSITIVE",
                        rule_name="Sensitive Information in Comments",
                        severity="low",
                        confidence="medium",
                        message=f"HTML comment may contain sensitive information ({pattern})",
                        url=url,
                        evidence=f"<!-- ...{pattern}... -->",
                        remediation="Remove sensitive information from HTML comments",
                        category="content"
                    ))
                    break

        return findings

    def _check_forms(self, url: str, content: str) -> List[WebFinding]:
        """Check form security."""
        findings = []

        # Find forms
        forms = re.findall(r'<form[^>]*action\s*=\s*["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                          content, re.DOTALL | re.IGNORECASE)

        for action, form_content in forms:
            # Check if form submits over HTTP
            if action.startswith('http://'):
                findings.append(WebFinding(
                    id=f"FORM-HTTP-{hash(url) % 10000}",
                    rule_id="FORM-HTTP",
                    rule_name="Form Over HTTP",
                    severity="high",
                    confidence="high",
                    message="Form submits to HTTP endpoint - credentials will be sent unencrypted",
                    url=url,
                    evidence=f"action=\"{action}\"",
                    remediation="Change form action to HTTPS",
                    category="forms"
                ))

            # Check for autocomplete on sensitive fields
            password_fields = re.findall(r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>',
                                        form_content, re.IGNORECASE)
            for field in password_fields:
                if 'autocomplete' not in field.lower():
                    findings.append(WebFinding(
                        id=f"FORM-AUTOCOMPLETE-{hash(url) % 10000}",
                        rule_id="FORM-AUTOCOMPLETE",
                        rule_name="Missing Autocomplete Attribute",
                        severity="low",
                        confidence="medium",
                        message="Password field missing autocomplete attribute",
                        url=url,
                        evidence=field[:100],
                        remediation="Add autocomplete=\"current-password\" or autocomplete=\"new-password\"",
                        category="forms"
                    ))
                    break

        return findings

    async def _check_sensitive_files(self, url: str) -> List[WebFinding]:
        """Check for exposed sensitive files."""
        findings = []
        sensitive_paths = [
            '.env', '.git/config', '.htaccess', 'robots.txt',
            'sitemap.xml', 'package.json', 'composer.lock',
            'requirements.txt', 'Dockerfile', '.DS_Store'
        ]

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Check a few common paths
        for path in ['.env', 'robots.txt', '.git/config']:
            try:
                test_url = urljoin(base, path)
                content, headers = await self._fetch_url(test_url)

                if content and len(content) > 0:
                    if path == '.env' and ('=' in content or 'SECRET' in content):
                        findings.append(WebFinding(
                            id=f"EXPOSED-ENV-{hash(url) % 10000}",
                            rule_id="EXPOSED-ENV",
                            rule_name="Exposed .env File",
                            severity="critical",
                            confidence="high",
                            message="Environment file is publicly accessible",
                            url=test_url,
                            evidence="File contains configuration variables",
                            remediation="Remove .env from web root, add to .htaccess or nginx deny",
                            category="exposure"
                        ))
                    elif path == '.git/config':
                        findings.append(WebFinding(
                            id=f"EXPOSED-GIT-{hash(url) % 10000}",
                            rule_id="EXPOSED-GIT",
                            rule_name="Exposed Git Repository",
                            severity="critical",
                            confidence="high",
                            message="Git repository is exposed",
                            url=test_url,
                            evidence=".git/config accessible",
                            remediation="Remove .git directory from web root or deny access",
                            category="exposure"
                        ))
            except:
                pass

        return findings

    def _check_cors_configuration(self, url: str, headers: dict) -> List[WebFinding]:
        """Check CORS configuration."""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        if 'access-control-allow-origin' in headers_lower:
            origin = headers_lower['access-control-allow-origin']
            if origin == '*':
                findings.append(WebFinding(
                    id=f"CORS-WILDCARD-{hash(url) % 10000}",
                    rule_id="CORS-WILDCARD",
                    rule_name="Permissive CORS",
                    severity="medium",
                    confidence="high",
                    message="Access-Control-Allow-Origin: * allows any origin",
                    url=url,
                    evidence="Header: Access-Control-Allow-Origin: *",
                    remediation="Restrict CORS to specific trusted origins",
                    category="cors"
                ))

        return findings

    def _check_server_exposure(self, headers: dict) -> List[WebFinding]:
        """Check for server information exposure."""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        if 'server' in headers_lower:
            server = headers_lower['server']
            # Check for version numbers
            if re.search(r'\d+\.\d+', server):
                findings.append(WebFinding(
                    id=f"SERVER-VERSION-{hash(server) % 10000}",
                    rule_id="SERVER-VERSION",
                    rule_name="Server Version Exposed",
                    severity="low",
                    confidence="high",
                    message=f"Server header reveals version: {server}",
                    url="N/A",
                    evidence=server,
                    remediation="Configure server to hide version information",
                    category="headers"
                ))

        return findings


class HTMLFileScanner:
    """Scanner for local HTML/CSS/JS files."""

    def __init__(self):
        self.findings: List[WebFinding] = []

    def scan_html_file(self, file_path: str, content: str = None) -> List[WebFinding]:
        """Scan HTML file for security issues."""
        findings = []

        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                return findings

        # Check for inline event handlers
        inline_events = re.findall(r'\son\w+\s*=\s*["\'][^"\']*["\']', content, re.IGNORECASE)
        if inline_events:
            findings.append(WebFinding(
                id=f"HTML-INLINE-EVENT-{hash(file_path) % 10000}",
                rule_id="HTML-INLINE-EVENT",
                rule_name="Inline Event Handlers",
                severity="low",
                confidence="medium",
                message=f"Found {len(inline_events)} inline event handlers",
                url=file_path,
                evidence="onclick=\"...\" onload=\"...\" etc",
                remediation="Move event handling to external JS files",
                category="html"
            ))

        # Check for target="_blank" without rel="noopener"
        links = re.findall(r'<a[^>]*href\s*=\s*["\'][^"\']*["\'][^>]*>', content, re.IGNORECASE)
        for link in links:
            if 'target=' in link and '_blank' in link and 'noopener' not in link:
                findings.append(WebFinding(
                    id=f"HTML-TARGET-{hash(file_path) % 10000}",
                    rule_id="HTML-TARGET",
                    rule_name="Unsafe target=\"_blank\"",
                    severity="medium",
                    confidence="high",
                    message="Links to external sites without rel=\"noopener noreferrer\"",
                    url=file_path,
                    evidence=link[:100],
                    remediation="Add rel=\"noopener noreferrer\" to external links",
                    category="html"
                ))
                break

        # Check for meta refresh
        meta_refresh = re.search(r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\']', content, re.IGNORECASE)
        if meta_refresh:
            findings.append(WebFinding(
                id=f"HTML-REFRESH-{hash(file_path) % 10000}",
                rule_id="HTML-REFRESH",
                rule_name="Meta Refresh",
                severity="low",
                confidence="medium",
                message="Meta refresh can be used for phishing attacks",
                url=file_path,
                evidence='<meta http-equiv="refresh">',
                remediation="Use HTTP redirects instead of meta refresh",
                category="html"
            ))

        # Check for external scripts (CDN without integrity)
        scripts = re.findall(r'<script[^>]*src\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>', content, re.IGNORECASE)
        for script in scripts:
            if 'integrity=' not in content[content.find(script):content.find(script)+200]:
                findings.append(WebFinding(
                    id=f"HTML-SCRIPT-INTEGRITY-{hash(file_path) % 10000}",
                    rule_id="HTML-SCRIPT-INTEGRITY",
                    rule_name="External Script Without Integrity",
                    severity="medium",
                    confidence="medium",
                    message="External script loaded without SRI hash",
                    url=file_path,
                    evidence=f"src=\"{script}\"",
                    remediation="Add integrity attribute with SRI hash",
                    category="html"
                ))
                break

        return findings

    def scan_css_file(self, file_path: str, content: str = None) -> List[WebFinding]:
        """Scan CSS file for security issues."""
        findings = []

        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                return findings

        # Check for expressions (IE only, but dangerous)
        if 'expression(' in content.lower():
            findings.append(WebFinding(
                id=f"CSS-EXPRESSION-{hash(file_path) % 10000}",
                rule_id="CSS-EXPRESSION",
                rule_name="CSS Expression",
                severity="high",
                confidence="high",
                message="CSS expression() found - can execute JavaScript",
                url=file_path,
                evidence="expression(...)",
                remediation="Remove CSS expressions, use standard CSS instead",
                category="css"
            ))

        # Check for @import of external stylesheets
        imports = re.findall(r'@import\s+(?:url\()?["\']([^"\']+)["\']', content, re.IGNORECASE)
        external_imports = [imp for imp in imports if imp.startswith('http')]
        if external_imports:
            findings.append(WebFinding(
                id=f"CSS-IMPORT-{hash(file_path) % 10000}",
                rule_id="CSS-IMPORT",
                rule_name="External CSS Import",
                severity="low",
                confidence="medium",
                message="External stylesheets imported via @import",
                url=file_path,
                evidence=f"@import url({external_imports[0]})",
                remediation="Consider hosting CSS locally or ensure HTTPS",
                category="css"
            ))

        return findings

    def scan_js_file(self, file_path: str, content: str = None) -> List[WebFinding]:
        """Scan JS file for security issues."""
        findings = []

        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                return findings

        # Check for debugger statements
        if 'debugger;' in content:
            findings.append(WebFinding(
                id=f"JS-DEBUGGER-{hash(file_path) % 10000}",
                rule_id="JS-DEBUGGER",
                rule_name="Debugger Statement",
                severity="info",
                confidence="high",
                message="debugger; statement found in production code",
                url=file_path,
                evidence="debugger;",
                remediation="Remove debugger statements before deployment",
                category="javascript"
            ))

        # Check for console.log in production
        if 'console.log' in content:
            findings.append(WebFinding(
                id=f"JS-CONSOLE-{hash(file_path) % 10000}",
                rule_id="JS-CONSOLE",
                rule_name="Console Logging",
                severity="info",
                confidence="low",
                message="console.log statements may expose sensitive data",
                url=file_path,
                evidence="console.log(...)",
                remediation="Remove console.log or use proper logging framework",
                category="javascript"
            ))

        return findings


def scan_website(url: str, output_format: str = "json") -> Dict[str, Any]:
    """Convenience function to scan a website."""
    scanner = WebSecurityScanner()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(scanner.scan_url(url))
    finally:
        loop.close()

    if output_format == "json":
        print(json.dumps(result, indent=2))

    return result
