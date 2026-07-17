"""Vulnerability intelligence knowledge base.

Maps scanner rule_ids to defensive threat intelligence:
risk impact, CVSS scores, CWE/OWASP refs, real-world CVEs,
remediation steps, and attack surface descriptions.

NO exploitation payloads or attack instructions.
"""

from typing import Dict, Any, Optional


# Knowledge base keyed by rule_id
VULN_INTEL_DB: Dict[str, Dict[str, Any]] = {

    # ─── SQL Injection ────────────────────────────────────────────
    "PY-SQLI-001": {
        "risk_impact": (
            "An attacker could read, modify, or delete the entire database contents. "
            "This can lead to mass data breaches, authentication bypass, privilege "
            "escalation, and full backend compromise. In severe cases, attackers can "
            "execute operating system commands through the database."
        ),
        "danger_level": 10,
        "danger_label": "Maximum Danger",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": "critical",
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "owasp_category": "A03:2021 – Injection",
        "owasp_url": "https://owasp.org/Top10/A03_2021-Injection/",
        "how_exploitable": (
            "SQL Injection occurs when untrusted data is concatenated directly into "
            "database queries. Attackers craft special input strings that alter the "
            "SQL command's logic, allowing them to bypass authentication, extract "
            "sensitive data, modify records, or execute system commands through the "
            "database. This is one of the most common and dangerous web vulnerabilities."
        ),
        "related_cves": [
            {
                "id": "CVE-2017-5638",
                "name": "Equifax Breach (Apache Struts)",
                "impact": "147 million records exposed",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-5638"
            },
            {
                "id": "CVE-2019-6340",
                "name": "Drupal SQL Injection",
                "impact": "Remote code execution via crafted requests",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-6340"
            },
            {
                "id": "CVE-2021-27928",
                "name": "MariaDB/MySQL Injection",
                "impact": "Arbitrary code execution through SQL injection",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-27928"
            }
        ],
        "remediation_steps": [
            "Use parameterized queries (prepared statements) for ALL database interactions",
            "Use an ORM like SQLAlchemy or Django ORM instead of raw SQL",
            "Apply input validation — whitelist expected characters, reject unexpected ones",
            "Enforce least-privilege database accounts (read-only where possible)",
            "Enable WAF (Web Application Firewall) rules for SQL injection patterns",
            "Conduct regular code reviews focusing on data access layers",
            "Implement query logging and anomaly detection for unusual SQL patterns"
        ],
        "safeguards": [
            {"step": "Use parameterized queries or prepared statements for ALL database calls", "priority": "critical"},
            {"step": "Adopt an ORM (SQLAlchemy, Django ORM) to abstract raw SQL", "priority": "high"},
            {"step": "Validate and sanitize all user inputs with whitelists", "priority": "high"},
            {"step": "Use least-privilege database accounts (read-only where possible)", "priority": "medium"},
            {"step": "Enable WAF rules that detect SQL injection patterns", "priority": "medium"},
            {"step": "Set up query logging and anomaly detection", "priority": "low"},
        ],
        "attack_surface": {
            "entry_points": ["HTTP request parameters", "Form inputs", "URL query strings", "API request bodies", "HTTP headers"],
            "data_flow": "User Input → Application Logic → SQL Query Builder → Database Engine",
            "trust_boundary": "The boundary between untrusted user input and the database query parser",
            "exposure_level": "high"
        }
    },

    # ─── Cross-Site Scripting (XSS) ──────────────────────────────
    "PY-XSS-001": {
        "risk_impact": (
            "An attacker could inject malicious scripts that execute in victims' browsers. "
            "This enables session hijacking, credential theft, defacement, phishing, "
            "keylogging, and redirection to malicious sites. Stored XSS can affect "
            "every user who views the compromised page."
        ),
        "danger_level": 7,
        "danger_label": "Severe Risk",
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "owasp_category": "A03:2021 – Injection",
        "owasp_url": "https://owasp.org/Top10/A03_2021-Injection/",
        "how_exploitable": (
            "Cross-Site Scripting happens when user-controlled content is rendered "
            "in a web page without proper sanitization. Malicious scripts injected "
            "this way execute in victims' browsers with full access to cookies, "
            "session tokens, and page content. This enables session hijacking, "
            "credential theft, and phishing attacks that appear to come from your site."
        ),
        "related_cves": [
            {
                "id": "CVE-2020-11022",
                "name": "jQuery XSS",
                "impact": "Cross-site scripting in jQuery < 3.5.0 affecting millions of sites",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-11022"
            },
            {
                "id": "CVE-2018-11776",
                "name": "Apache Struts XSS",
                "impact": "Remote code execution via crafted URL",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-11776"
            },
            {
                "id": "CVE-2021-41184",
                "name": "jQuery UI XSS",
                "impact": "XSS in jQuery UI Datepicker affecting enterprise applications",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41184"
            }
        ],
        "remediation_steps": [
            "Escape all user-controlled output using context-aware encoding (HTML, JS, URL, CSS)",
            "Use a templating engine with auto-escaping enabled (Jinja2, React JSX)",
            "Implement Content Security Policy (CSP) headers to restrict script sources",
            "Sanitize HTML input using a whitelist-based library (e.g., bleach, DOMPurify)",
            "Set HttpOnly and Secure flags on session cookies to limit XSS impact",
            "Validate and sanitize all inputs on the server side",
            "Use Subresource Integrity (SRI) for external scripts"
        ],
        "safeguards": [
            {"step": "Enable auto-escaping in your template engine (Jinja2, React JSX)", "priority": "critical"},
            {"step": "Sanitize HTML with a whitelist library (DOMPurify, bleach)", "priority": "high"},
            {"step": "Deploy Content Security Policy headers", "priority": "high"},
            {"step": "Set HttpOnly + Secure flags on all session cookies", "priority": "high"},
            {"step": "Use Subresource Integrity (SRI) for external scripts", "priority": "medium"},
            {"step": "Validate all inputs server-side, not just client-side", "priority": "medium"},
        ],
        "attack_surface": {
            "entry_points": ["Form inputs", "URL parameters", "HTTP headers (Referer, User-Agent)", "File uploads (SVG, HTML)", "WebSocket messages"],
            "data_flow": "User Input → Server Processing → HTML Response → Victim's Browser",
            "trust_boundary": "The boundary between server-generated content and the browser's DOM parser",
            "exposure_level": "high"
        }
    },

    # ─── Authentication / Authorization Issues ───────────────────
    "PY-AUTH-001": {
        "risk_impact": (
            "Weak authentication allows attackers to impersonate legitimate users, "
            "bypass login mechanisms, or escalate privileges. This can lead to "
            "unauthorized access to sensitive data, administrative takeover, and "
            "complete system compromise."
        ),
        "danger_level": 9,
        "danger_label": "Extreme Danger",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_severity": "high",
        "cwe_id": "CWE-287",
        "cwe_name": "Improper Authentication",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "owasp_url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "how_exploitable": (
            "Authentication weaknesses — such as hardcoded secrets, weak algorithms, "
            "or missing security flags — allow attackers to forge sessions, bypass "
            "login mechanisms, or impersonate users. Even a single misconfigured "
            "JWT secret or missing cookie flag can grant full administrative access."
        ),
        "related_cves": [
            {
                "id": "CVE-2021-44228",
                "name": "Log4Shell",
                "impact": "Remote code execution affecting millions of Java applications",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
            },
            {
                "id": "CVE-2023-22515",
                "name": "Atlassian Confluence Auth Bypass",
                "impact": "Unauthorized admin account creation",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-22515"
            },
            {
                "id": "CVE-2022-22965",
                "name": "Spring4Shell",
                "impact": "Authentication bypass leading to RCE in Spring Framework",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"
            }
        ],
        "remediation_steps": [
            "Use strong password hashing (bcrypt, scrypt, Argon2) — never store plaintext",
            "Implement multi-factor authentication (MFA) for sensitive operations",
            "Use established auth frameworks (OAuth 2.0, OpenID Connect) instead of custom logic",
            "Enforce account lockout after repeated failed login attempts",
            "Implement proper session management with secure, random session tokens",
            "Apply principle of least privilege for all user roles",
            "Log and monitor authentication events for anomaly detection"
        ],
        "safeguards": [
            {"step": "Store secrets in environment variables, never in source code", "priority": "critical"},
            {"step": "Use strong password hashing (bcrypt/Argon2) with unique salts", "priority": "critical"},
            {"step": "Enable multi-factor authentication for admin/sensitive operations", "priority": "high"},
            {"step": "Use established auth libraries (OAuth 2.0, Passport.js)", "priority": "high"},
            {"step": "Implement account lockout after repeated failures", "priority": "medium"},
            {"step": "Log and monitor all authentication events", "priority": "medium"},
        ],
        "attack_surface": {
            "entry_points": ["Login endpoints", "Password reset flows", "API token endpoints", "Session cookies", "OAuth callbacks"],
            "data_flow": "Credentials → Authentication Logic → Session Manager → Protected Resources",
            "trust_boundary": "The boundary between unauthenticated and authenticated application zones",
            "exposure_level": "critical"
        }
    },

    # ─── HTTPS Not Enforced ──────────────────────────────────────
    "HTTPS-001": {
        "risk_impact": (
            "All data between the user and server is transmitted in plaintext, "
            "including passwords, session tokens, and personal information. Any "
            "attacker on the same network can intercept and read this traffic."
        ),
        "danger_level": 8,
        "danger_label": "Critical Risk",
        "cvss_score": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_severity": "high",
        "cwe_id": "CWE-319",
        "cwe_name": "Cleartext Transmission of Sensitive Information",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "how_exploitable": (
            "Without HTTPS, all data travels unencrypted. On shared WiFi, corporate "
            "networks, or through compromised routers, attackers can passively monitor "
            "all traffic to read passwords, tokens, and personal data as it flows."
        ),
        "related_cves": [
            {
                "id": "CVE-2014-3566",
                "name": "POODLE Attack",
                "impact": "Downgrade attack forcing SSL 3.0 to decrypt traffic",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-3566"
            }
        ],
        "remediation_steps": [
            "Enable HTTPS with a valid TLS certificate (Let's Encrypt is free)",
            "Redirect all HTTP requests to HTTPS (301 redirect)",
            "Add HSTS header to prevent future HTTP connections",
            "Use TLS 1.2 or higher exclusively"
        ],
        "safeguards": [
            {"step": "Obtain and install a valid TLS certificate", "priority": "critical"},
            {"step": "Configure HTTP→HTTPS 301 redirects on all routes", "priority": "critical"},
            {"step": "Add Strict-Transport-Security header with long max-age", "priority": "high"},
            {"step": "Disable TLS 1.0 and 1.1 on the server", "priority": "high"},
        ],
        "attack_surface": {
            "entry_points": ["All HTTP endpoints", "Login forms", "API requests"],
            "data_flow": "User Browser → [Plaintext HTTP] → Web Server",
            "trust_boundary": "The network between client and server",
            "exposure_level": "high"
        }
    },

    # ─── Missing Security Headers ────────────────────────────────
    "HEADER-Strict-Transport-Security": {
        "risk_impact": "Site vulnerable to SSL stripping attacks on first visit.",
        "danger_level": 6,
        "danger_label": "High Risk",
        "cvss_score": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-523",
        "cwe_name": "Unprotected Transport of Credentials",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": (
            "Without HSTS, browsers may connect over plain HTTP even after visiting "
            "the HTTPS version. Attackers on the same network can intercept and modify "
            "this unencrypted traffic (SSL stripping)."
        ),
        "related_cves": [],
        "remediation_steps": [
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "Consider adding preload directive for browser preload lists"
        ],
        "safeguards": [
            {"step": "Add HSTS header with max-age of at least 1 year", "priority": "high"},
            {"step": "Include subdomains in HSTS policy", "priority": "medium"},
            {"step": "Submit domain to HSTS preload list", "priority": "low"},
        ],
        "attack_surface": {
            "entry_points": ["First HTTP request before redirect"],
            "data_flow": "Browser → HTTP Request → Interceptor → Server",
            "trust_boundary": "Initial unencrypted connection before HTTPS redirect",
            "exposure_level": "medium"
        }
    },

    "HEADER-Content-Security-Policy": {
        "risk_impact": "XSS protection is significantly reduced without CSP.",
        "danger_level": 7,
        "danger_label": "Severe Risk",
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-1021",
        "cwe_name": "Improper Restriction of Rendered UI Layers",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": (
            "Without CSP, browsers execute any script injected into pages. CSP is a "
            "whitelist that tells browsers which script sources are legitimate. Without "
            "it, a single XSS flaw becomes much more exploitable."
        ),
        "related_cves": [],
        "remediation_steps": [
            "Add Content-Security-Policy header with strict directives",
            "Start with report-only mode to avoid breaking functionality",
            "Eliminate unsafe-inline and unsafe-eval from CSP"
        ],
        "safeguards": [
            {"step": "Deploy CSP in report-only mode first to identify issues", "priority": "high"},
            {"step": "Restrict script-src to self and trusted CDNs only", "priority": "high"},
            {"step": "Remove unsafe-inline and unsafe-eval directives", "priority": "medium"},
        ],
        "attack_surface": {
            "entry_points": ["Script injection points", "Inline event handlers"],
            "data_flow": "Injected Script → Browser DOM → Cookie/Session Access",
            "trust_boundary": "Browser's script execution policy",
            "exposure_level": "high"
        }
    },

    "HEADER-X-Frame-Options": {
        "risk_impact": "Site can be embedded in iframes for clickjacking attacks.",
        "danger_level": 5,
        "danger_label": "Significant Risk",
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-1021",
        "cwe_name": "Improper Restriction of Rendered UI Layers",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": (
            "Without X-Frame-Options, your site can be embedded in an invisible "
            "iframe on an attacker's page, tricking users into clicking actions "
            "they didn't intend (clickjacking)."
        ),
        "related_cves": [],
        "remediation_steps": [
            "Add X-Frame-Options: DENY or SAMEORIGIN header",
            "Also set frame-ancestors directive in CSP"
        ],
        "safeguards": [
            {"step": "Add X-Frame-Options: DENY to all responses", "priority": "high"},
            {"step": "Set CSP frame-ancestors to 'none' or 'self'", "priority": "medium"},
        ],
        "attack_surface": {
            "entry_points": ["Pages with sensitive actions (forms, buttons)"],
            "data_flow": "Victim Browser → Attacker Page (iframe) → Your Site",
            "trust_boundary": "Browser frame embedding policy",
            "exposure_level": "medium"
        }
    },

    "HEADER-X-Content-Type-Options": {
        "risk_impact": "Browser may misinterpret file types, enabling script execution.",
        "danger_level": 3,
        "danger_label": "Moderate Risk",
        "cvss_score": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "cvss_severity": "low",
        "cwe_id": "CWE-16",
        "cwe_name": "Configuration",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": (
            "Without nosniff, browsers may 'guess' the content type of responses, "
            "potentially interpreting uploaded files as executable scripts."
        ),
        "related_cves": [],
        "remediation_steps": ["Add X-Content-Type-Options: nosniff header"],
        "safeguards": [
            {"step": "Add X-Content-Type-Options: nosniff to all responses", "priority": "medium"},
        ],
        "attack_surface": {
            "entry_points": ["File upload endpoints", "Static file serving"],
            "data_flow": "Uploaded File → Server Response → Browser MIME Sniffing",
            "trust_boundary": "Browser's content-type interpretation",
            "exposure_level": "low"
        }
    },

    "HEADER-Referrer-Policy": {
        "risk_impact": "Referrer URLs may leak sensitive paths and tokens to third parties.",
        "danger_level": 3,
        "danger_label": "Moderate Risk",
        "cvss_score": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cvss_severity": "low",
        "cwe_id": "CWE-200",
        "cwe_name": "Information Exposure",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": (
            "Without a Referrer-Policy, browsers send full page URLs to third-party "
            "sites when users click links, potentially leaking session tokens, "
            "internal paths, and user data."
        ),
        "related_cves": [],
        "remediation_steps": ["Add Referrer-Policy: strict-origin-when-cross-origin"],
        "safeguards": [
            {"step": "Add Referrer-Policy: strict-origin-when-cross-origin", "priority": "medium"},
        ],
        "attack_surface": {
            "entry_points": ["Outbound links to third-party sites"],
            "data_flow": "User Navigation → Referrer Header → Third-party Server",
            "trust_boundary": "Cross-origin referrer data transmission",
            "exposure_level": "low"
        }
    },

    "HEADER-Permissions-Policy": {
        "risk_impact": "Browser features (camera, mic, geolocation) not restricted.",
        "danger_level": 2,
        "danger_label": "Low Risk",
        "cvss_score": 2.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cvss_severity": "low",
        "cwe_id": "CWE-16",
        "cwe_name": "Configuration",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": (
            "Without Permissions-Policy, embedded third-party content (ads, iframes) "
            "could access powerful browser APIs like camera or geolocation."
        ),
        "related_cves": [],
        "remediation_steps": ["Add Permissions-Policy to restrict unused browser features"],
        "safeguards": [
            {"step": "Add Permissions-Policy disabling unused APIs", "priority": "low"},
        ],
        "attack_surface": {
            "entry_points": ["Third-party scripts and iframes"],
            "data_flow": "Third-party Code → Browser API → User Device",
            "trust_boundary": "Browser feature access policy",
            "exposure_level": "low"
        }
    },

    # ─── SSL/TLS Issues ──────────────────────────────────────────
    "TLS-OLD": {
        "risk_impact": "Outdated TLS allows traffic decryption via known attacks.",
        "danger_level": 8,
        "danger_label": "Critical Risk",
        "cvss_score": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_severity": "high",
        "cwe_id": "CWE-326",
        "cwe_name": "Inadequate Encryption Strength",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "how_exploitable": (
            "TLS 1.0/1.1 have known cryptographic weaknesses (BEAST, POODLE) that "
            "allow attackers to decrypt traffic. All major browsers have deprecated "
            "these versions."
        ),
        "related_cves": [
            {"id": "CVE-2014-3566", "name": "POODLE", "impact": "SSL 3.0 padding oracle attack", "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-3566"},
            {"id": "CVE-2011-3389", "name": "BEAST", "impact": "TLS 1.0 CBC cipher attack", "url": "https://nvd.nist.gov/vuln/detail/CVE-2011-3389"}
        ],
        "remediation_steps": ["Disable TLS 1.0/1.1", "Enable TLS 1.2+ only", "Use strong cipher suites"],
        "safeguards": [
            {"step": "Disable TLS 1.0 and 1.1 in server configuration", "priority": "critical"},
            {"step": "Enable only TLS 1.2 and TLS 1.3", "priority": "critical"},
            {"step": "Configure strong cipher suites (ECDHE, AES-GCM)", "priority": "high"},
        ],
        "attack_surface": {
            "entry_points": ["TLS handshake", "All encrypted connections"],
            "data_flow": "Client → TLS Handshake → Weak Protocol → Server",
            "trust_boundary": "TLS protocol negotiation",
            "exposure_level": "high"
        }
    },

    "CERT-EXP": {
        "risk_impact": "Expired certificate causes browser warnings and possible fallback to HTTP.",
        "danger_level": 6,
        "danger_label": "High Risk",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-295",
        "cwe_name": "Improper Certificate Validation",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "how_exploitable": (
            "An expired certificate triggers browser warnings, training users to "
            "ignore security alerts. If not renewed, traffic may fall back to HTTP."
        ),
        "related_cves": [],
        "remediation_steps": ["Renew SSL certificate before expiry", "Set up auto-renewal (certbot)"],
        "safeguards": [
            {"step": "Renew the certificate immediately", "priority": "critical"},
            {"step": "Set up automated certificate renewal (e.g., certbot)", "priority": "high"},
            {"step": "Configure certificate expiry monitoring/alerts", "priority": "medium"},
        ],
        "attack_surface": {
            "entry_points": ["All HTTPS connections"],
            "data_flow": "Client → Certificate Validation → Expired Cert → Warning/Bypass",
            "trust_boundary": "Certificate validity check",
            "exposure_level": "medium"
        }
    },

    "SSL-ERR": {
        "risk_impact": "SSL/TLS misconfiguration may prevent secure connections entirely.",
        "danger_level": 7,
        "danger_label": "Severe Risk",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-295",
        "cwe_name": "Improper Certificate Validation",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "how_exploitable": (
            "SSL/TLS errors indicate the secure connection cannot be established "
            "properly, meaning data may travel unencrypted or the server identity "
            "cannot be verified."
        ),
        "related_cves": [],
        "remediation_steps": ["Check SSL certificate chain", "Verify server configuration", "Test with SSL Labs"],
        "safeguards": [
            {"step": "Test SSL configuration with Qualys SSL Labs", "priority": "high"},
            {"step": "Ensure full certificate chain is installed", "priority": "high"},
            {"step": "Verify server name matches certificate CN/SAN", "priority": "high"},
        ],
        "attack_surface": {
            "entry_points": ["TLS handshake"],
            "data_flow": "Client → TLS Negotiation → Error → Fallback/Rejection",
            "trust_boundary": "TLS connection establishment",
            "exposure_level": "high"
        }
    },

    # ─── CORS Issues ─────────────────────────────────────────────
    "CORS-WILDCARD": {
        "risk_impact": "Any website can make authenticated cross-origin requests to your API.",
        "danger_level": 6,
        "danger_label": "High Risk",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-942",
        "cwe_name": "Permissive Cross-domain Policy",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": (
            "A wildcard CORS origin allows any website to make requests to your API. "
            "Malicious sites can read user-specific data by making requests from the "
            "victim's browser with their cookies."
        ),
        "related_cves": [],
        "remediation_steps": ["Restrict Access-Control-Allow-Origin to specific trusted origins"],
        "safeguards": [
            {"step": "Replace wildcard (*) with explicit allowed origins", "priority": "high"},
            {"step": "Validate Origin header server-side against a whitelist", "priority": "high"},
            {"step": "Never combine wildcard CORS with credentials", "priority": "critical"},
        ],
        "attack_surface": {
            "entry_points": ["All API endpoints returning user-specific data"],
            "data_flow": "Malicious Site → Cross-origin Request → Your API → User Data",
            "trust_boundary": "Cross-origin request policy",
            "exposure_level": "medium"
        }
    },

    # ─── Exposed Files ───────────────────────────────────────────
    "EXPOSED-ENV": {
        "risk_impact": "Database credentials, API keys, and secrets are publicly accessible.",
        "danger_level": 10,
        "danger_label": "Maximum Danger",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": "critical",
        "cwe_id": "CWE-540",
        "cwe_name": "Inclusion of Sensitive Information in Source Code",
        "owasp_category": "A01:2021 – Broken Access Control",
        "owasp_url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "how_exploitable": (
            "An exposed .env file reveals all configuration secrets. With these, "
            "attackers directly access databases, cloud services, and internal systems."
        ),
        "related_cves": [],
        "remediation_steps": [
            "Remove .env from web root immediately",
            "Rotate all exposed credentials",
            "Add .env to server deny rules"
        ],
        "safeguards": [
            {"step": "Remove .env file from web-accessible directory immediately", "priority": "critical"},
            {"step": "Rotate ALL credentials found in the exposed file", "priority": "critical"},
            {"step": "Block access to dotfiles in web server config", "priority": "high"},
            {"step": "Audit access logs for prior unauthorized access", "priority": "high"},
        ],
        "attack_surface": {
            "entry_points": ["Direct URL access to /.env"],
            "data_flow": "Attacker → HTTP GET /.env → Server → Secrets",
            "trust_boundary": "Web server file access control",
            "exposure_level": "critical"
        }
    },

    "EXPOSED-GIT": {
        "risk_impact": "Full source code and commit history downloadable by anyone.",
        "danger_level": 9,
        "danger_label": "Extreme Danger",
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_severity": "high",
        "cwe_id": "CWE-538",
        "cwe_name": "Insertion of Sensitive Information into Externally-Accessible File",
        "owasp_category": "A01:2021 – Broken Access Control",
        "owasp_url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "how_exploitable": (
            "An exposed .git directory allows downloading your entire source code, "
            "including credentials in commit history and internal comments."
        ),
        "related_cves": [],
        "remediation_steps": ["Remove .git from web root", "Deny access to .git in server config"],
        "safeguards": [
            {"step": "Remove or deny access to .git directory", "priority": "critical"},
            {"step": "Check commit history for leaked secrets and rotate them", "priority": "critical"},
            {"step": "Block all dotfile/dotdirectory access in web server", "priority": "high"},
        ],
        "attack_surface": {
            "entry_points": ["Direct URL access to /.git/config"],
            "data_flow": "Attacker → HTTP GET /.git/* → Full Source Reconstruction",
            "trust_boundary": "Web server directory listing and file access control",
            "exposure_level": "critical"
        }
    },

    # ─── Form Issues ─────────────────────────────────────────────
    "FORM-HTTP": {
        "risk_impact": "Form credentials transmitted in plaintext over the network.",
        "danger_level": 8,
        "danger_label": "Critical Risk",
        "cvss_score": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_severity": "high",
        "cwe_id": "CWE-319",
        "cwe_name": "Cleartext Transmission of Sensitive Information",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "how_exploitable": (
            "Forms submitting over HTTP send credentials in plain text. Anyone "
            "monitoring the network can read usernames, passwords, and personal data."
        ),
        "related_cves": [],
        "remediation_steps": ["Change form action to HTTPS", "Enable HTTPS on the entire site"],
        "safeguards": [
            {"step": "Change all form actions to HTTPS URLs", "priority": "critical"},
            {"step": "Enable HTTPS site-wide with automatic redirects", "priority": "critical"},
            {"step": "Add HSTS to prevent HTTP fallback", "priority": "high"},
        ],
        "attack_surface": {
            "entry_points": ["Login forms", "Registration forms", "Payment forms"],
            "data_flow": "User Form Input → HTTP POST → [Plaintext] → Server",
            "trust_boundary": "Network transport between client and server",
            "exposure_level": "high"
        }
    },

    "FORM-AUTOCOMPLETE": {
        "risk_impact": "Browser may cache passwords on shared or public devices.",
        "danger_level": 3,
        "danger_label": "Moderate Risk",
        "cvss_score": 3.3,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_severity": "low",
        "cwe_id": "CWE-525",
        "cwe_name": "Information Exposure Through Browser Caching",
        "owasp_category": "A04:2021 – Insecure Design",
        "owasp_url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "how_exploitable": (
            "Without explicit autocomplete attributes, browsers may store passwords "
            "and autofill them on shared devices, exposing credentials to other users."
        ),
        "related_cves": [],
        "remediation_steps": ["Add autocomplete='current-password' or 'new-password' to password fields"],
        "safeguards": [
            {"step": "Add appropriate autocomplete attributes to all sensitive fields", "priority": "medium"},
        ],
        "attack_surface": {
            "entry_points": ["Password fields", "Credit card fields"],
            "data_flow": "User Input → Browser Autofill Cache → Next User",
            "trust_boundary": "Browser credential storage",
            "exposure_level": "low"
        }
    },

    # ─── Content Issues ──────────────────────────────────────────
    "MIXED-CONTENT": {
        "risk_impact": "HTTP resources on HTTPS page can be intercepted or modified.",
        "danger_level": 5,
        "danger_label": "Significant Risk",
        "cvss_score": 4.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-311",
        "cwe_name": "Missing Encryption of Sensitive Data",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "how_exploitable": (
            "Loading HTTP resources on an HTTPS page allows attackers to intercept "
            "and modify those resources. A compromised script or stylesheet can "
            "then take over the entire page."
        ),
        "related_cves": [],
        "remediation_steps": ["Load all resources over HTTPS", "Use protocol-relative URLs"],
        "safeguards": [
            {"step": "Update all resource URLs to use HTTPS", "priority": "high"},
            {"step": "Add upgrade-insecure-requests CSP directive", "priority": "medium"},
        ],
        "attack_surface": {
            "entry_points": ["External scripts, stylesheets, images loaded over HTTP"],
            "data_flow": "HTTPS Page → HTTP Resource → Attacker Intercept → Modified Content",
            "trust_boundary": "Mixed HTTP/HTTPS content loading",
            "exposure_level": "medium"
        }
    },

    # ─── Information Disclosure ──────────────────────────────────
    "HEADER-LEAK": {
        "risk_impact": "Technology stack revealed to potential attackers.",
        "danger_level": 2,
        "danger_label": "Low Risk",
        "cvss_score": 2.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cvss_severity": "low",
        "cwe_id": "CWE-200",
        "cwe_name": "Information Exposure",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": (
            "X-Powered-By header reveals the technology stack, helping attackers "
            "identify known vulnerabilities specific to your framework version."
        ),
        "related_cves": [],
        "remediation_steps": ["Remove X-Powered-By header from server configuration"],
        "safeguards": [
            {"step": "Remove X-Powered-By header in server config", "priority": "medium"},
            {"step": "Remove all version-revealing headers", "priority": "medium"},
        ],
        "attack_surface": {
            "entry_points": ["HTTP response headers"],
            "data_flow": "Server → Response Headers → Attacker Fingerprinting",
            "trust_boundary": "Server response metadata",
            "exposure_level": "low"
        }
    },

    "CSP-WEAK": {
        "risk_impact": "CSP allows unsafe-inline/eval, reducing XSS protection.",
        "danger_level": 5,
        "danger_label": "Significant Risk",
        "cvss_score": 5.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-16",
        "cwe_name": "Configuration",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": (
            "CSP with unsafe-inline or unsafe-eval effectively disables XSS "
            "protection, since attackers can inject inline scripts or use eval()."
        ),
        "related_cves": [],
        "remediation_steps": ["Remove unsafe-inline and unsafe-eval", "Use CSP nonces or hashes"],
        "safeguards": [
            {"step": "Replace unsafe-inline with CSP nonces or hashes", "priority": "high"},
            {"step": "Remove unsafe-eval and refactor code to avoid eval()", "priority": "high"},
        ],
        "attack_surface": {
            "entry_points": ["Inline scripts", "eval() calls"],
            "data_flow": "Injected Script → Bypasses Weak CSP → Full DOM Access",
            "trust_boundary": "CSP policy enforcement",
            "exposure_level": "medium"
        }
    },

    "SERVER-VERSION": {
        "risk_impact": "Server version information helps attackers target known vulnerabilities.",
        "danger_level": 2,
        "danger_label": "Low Risk",
        "cvss_score": 2.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cvss_severity": "low",
        "cwe_id": "CWE-200",
        "cwe_name": "Information Exposure",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": (
            "Server version headers help attackers look up specific CVEs and "
            "known exploits for that exact version."
        ),
        "related_cves": [],
        "remediation_steps": ["Configure server to hide version information"],
        "safeguards": [
            {"step": "Remove or mask the Server header", "priority": "medium"},
            {"step": "Keep server software updated regardless", "priority": "high"},
        ],
        "attack_surface": {
            "entry_points": ["HTTP Server header"],
            "data_flow": "Server → Response Header → Attacker Version Lookup",
            "trust_boundary": "Server response metadata",
            "exposure_level": "low"
        }
    },

    # ─── HTML/CSS File Issues ────────────────────────────────────
    "HTML-INLINE-EVENT": {
        "risk_impact": "Inline event handlers bypass CSP and increase XSS risk.",
        "danger_level": 3,
        "danger_label": "Moderate Risk",
        "cvss_score": 3.7,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_severity": "low",
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "owasp_category": "A03:2021 – Injection",
        "owasp_url": "https://owasp.org/Top10/A03_2021-Injection/",
        "how_exploitable": "Inline event handlers (onclick, onload) execute JavaScript directly in HTML, bypassing CSP protections.",
        "related_cves": [],
        "remediation_steps": ["Move event handling to external JS files"],
        "safeguards": [{"step": "Move all inline event handlers to external JavaScript", "priority": "medium"}],
        "attack_surface": {"entry_points": ["HTML attributes"], "data_flow": "HTML Attribute → Browser JS Engine", "trust_boundary": "CSP inline script policy", "exposure_level": "low"}
    },

    "HTML-TARGET": {
        "risk_impact": "External links can access your page via window.opener.",
        "danger_level": 4,
        "danger_label": "Elevated Risk",
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-1022",
        "cwe_name": "Use of Web Link to Untrusted Target with window.opener Access",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": "Links with target='_blank' without rel='noopener' allow the opened page to redirect your page via window.opener.location.",
        "related_cves": [],
        "remediation_steps": ["Add rel='noopener noreferrer' to external links"],
        "safeguards": [{"step": "Add rel='noopener noreferrer' to all target='_blank' links", "priority": "medium"}],
        "attack_surface": {"entry_points": ["External links"], "data_flow": "User Click → New Tab → window.opener → Your Page", "trust_boundary": "Cross-window navigation", "exposure_level": "medium"}
    },

    "HTML-SCRIPT-INTEGRITY": {
        "risk_impact": "External scripts without SRI can be tampered with at the CDN.",
        "danger_level": 5,
        "danger_label": "Significant Risk",
        "cvss_score": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-353",
        "cwe_name": "Missing Support for Integrity Check",
        "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        "owasp_url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "how_exploitable": "Without SRI hashes, if a CDN is compromised, modified scripts execute on all sites loading from it.",
        "related_cves": [{"id": "CVE-2019-11358", "name": "jQuery Prototype Pollution", "impact": "CDN-served jQuery vulnerability affecting millions", "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-11358"}],
        "remediation_steps": ["Add integrity attribute with SRI hash to external scripts"],
        "safeguards": [
            {"step": "Generate and add SRI hashes for all external scripts", "priority": "high"},
            {"step": "Use crossorigin='anonymous' with SRI", "priority": "medium"},
        ],
        "attack_surface": {"entry_points": ["CDN-served scripts"], "data_flow": "CDN → Modified Script → Your Page → User Browser", "trust_boundary": "CDN integrity", "exposure_level": "medium"}
    },

    "CSS-EXPRESSION": {
        "risk_impact": "CSS expressions execute JavaScript, enabling code injection.",
        "danger_level": 7,
        "danger_label": "Severe Risk",
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "owasp_category": "A03:2021 – Injection",
        "owasp_url": "https://owasp.org/Top10/A03_2021-Injection/",
        "how_exploitable": "CSS expression() evaluates JavaScript within stylesheets, bypassing typical script-focused protections.",
        "related_cves": [],
        "remediation_steps": ["Remove CSS expressions, use standard CSS instead"],
        "safeguards": [{"step": "Replace all CSS expressions with standard CSS properties", "priority": "critical"}],
        "attack_surface": {"entry_points": ["CSS files", "Inline styles"], "data_flow": "CSS expression() → JavaScript Engine → DOM", "trust_boundary": "CSS parser security", "exposure_level": "medium"}
    },

    # ─── Generic Web Vulnerability (fallback) ────────────────────
    "WEB-GENERIC": {
        "risk_impact": (
            "Web configuration and header vulnerabilities can expose the application "
            "to various attacks including clickjacking, MIME-type sniffing, information "
            "disclosure, and man-in-the-middle attacks. While individually lower risk, "
            "these issues are often chained together for larger attacks."
        ),
        "danger_level": 5,
        "danger_label": "Significant Risk",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_severity": "medium",
        "cwe_id": "CWE-16",
        "cwe_name": "Configuration",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "how_exploitable": (
            "Security misconfigurations in headers, TLS, and server responses expose "
            "your application to various attacks. Missing security headers remove "
            "browser-enforced protections, while information disclosure helps attackers "
            "fingerprint your stack and plan targeted attacks."
        ),
        "related_cves": [
            {
                "id": "CVE-2019-5418",
                "name": "Rails File Disclosure",
                "impact": "Arbitrary file reading via misconfigured Accept headers",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-5418"
            },
            {
                "id": "CVE-2020-1938",
                "name": "Apache Tomcat Ghostcat",
                "impact": "File read/inclusion via misconfigured AJP connector",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
            }
        ],
        "remediation_steps": [
            "Set security headers: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security",
            "Enable Content Security Policy (CSP) with strict directives",
            "Disable unnecessary HTTP methods (TRACE, OPTIONS in production)",
            "Remove server version headers and debug information",
            "Configure CORS with specific allowed origins — never use wildcard in production",
            "Implement HTTPS everywhere with valid TLS certificates",
            "Regularly audit server configurations against security benchmarks (CIS)"
        ],
        "safeguards": [
            {"step": "Add all recommended security headers", "priority": "high"},
            {"step": "Enforce HTTPS with valid TLS 1.2+ certificates", "priority": "high"},
            {"step": "Remove server version and debug headers", "priority": "medium"},
            {"step": "Restrict CORS to specific trusted origins", "priority": "medium"},
            {"step": "Disable unnecessary HTTP methods", "priority": "low"},
            {"step": "Audit config against CIS benchmarks regularly", "priority": "low"},
        ],
        "attack_surface": {
            "entry_points": ["HTTP headers", "Server configuration", "TLS settings", "CORS policy", "Error pages"],
            "data_flow": "HTTP Request → Web Server Config → Response Headers → Client Browser",
            "trust_boundary": "The boundary between the web server's configuration and the client's trust model",
            "exposure_level": "medium"
        }
    },
}


def get_intel(rule_id: str) -> Optional[Dict[str, Any]]:
    """Look up vulnerability intelligence for a given rule_id.

    Tries exact match first, then prefix matching for header rules,
    falls back to WEB-GENERIC for unknown web scanner findings,
    or returns None if no intel is available.
    """
    if rule_id in VULN_INTEL_DB:
        return VULN_INTEL_DB[rule_id]

    # Try matching header rule IDs (e.g., HEADER-Strict-Transport-Security-12345)
    for key in VULN_INTEL_DB:
        if rule_id.startswith(key):
            return VULN_INTEL_DB[key]

    # Fallback for web scanner findings
    if rule_id.startswith(("WEB-", "web-", "HEADER-", "HTTPS-", "TLS-", "SSL-",
                           "CORS-", "FORM-", "CERT-", "EXPOSED-", "MIXED-",
                           "SCRIPT-", "STYLE-", "COMMENT-", "SERVER-", "CSP-",
                           "HTML-", "CSS-")):
        return VULN_INTEL_DB.get("WEB-GENERIC")

    return None


def enrich_finding(finding_dict: Dict[str, Any], rule_id: str) -> Dict[str, Any]:
    """Enrich a finding dict with vulnerability intelligence and AI analysis.

    Adds 'intel' and 'ai_analysis' keys to the finding dict.
    """
    intel = get_intel(rule_id)
    if intel:
        finding_dict["intel"] = intel
    else:
        finding_dict["intel"] = None

    # Add AI analysis
    from scanner.ai_analyzer import enrich_finding_with_ai
    finding_dict = enrich_finding_with_ai(finding_dict, rule_id)

    return finding_dict
