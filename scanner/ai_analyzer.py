"""AI-powered threat analysis engine.

Generates contextual analysis for each finding including:
- Danger rating with visual indicator
- Exploitation summary (defensive, educational)
- Impact description
- Prioritized safeguard checklist
- Related attack technique names

Uses template-based generation from the vuln_intel KB.
No external API calls required.
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from scanner.vuln_intel import get_intel, VULN_INTEL_DB


# ── Danger Level Definitions ──────────────────────────────────────

DANGER_LEVELS = {
    1:  {"label": "Minimal Risk",     "emoji": "🟢", "color": "green"},
    2:  {"label": "Low Risk",         "emoji": "🟢", "color": "green"},
    3:  {"label": "Moderate Risk",    "emoji": "🟡", "color": "yellow"},
    4:  {"label": "Elevated Risk",    "emoji": "🟡", "color": "yellow"},
    5:  {"label": "Significant Risk", "emoji": "🟠", "color": "orange"},
    6:  {"label": "High Risk",        "emoji": "🟠", "color": "orange"},
    7:  {"label": "Severe Risk",      "emoji": "🔴", "color": "red"},
    8:  {"label": "Critical Risk",    "emoji": "🔴", "color": "red"},
    9:  {"label": "Extreme Danger",   "emoji": "⚫", "color": "darkred"},
    10: {"label": "Maximum Danger",   "emoji": "⚫", "color": "darkred"},
}


# ── Exploitation Summaries by Vulnerability Class ─────────────────
# These are DEFENSIVE explanations to help developers understand
# WHY fixes matter. They describe attack classes, not techniques.

EXPLOITATION_SUMMARIES = {
    "PY-SQLI-001": (
        "SQL Injection occurs when untrusted data is concatenated directly into "
        "database queries. Attackers craft special input strings that alter the "
        "SQL command's logic, allowing them to bypass authentication, extract "
        "sensitive data, modify records, or even execute system commands through "
        "the database. This is one of the most common and dangerous web vulnerabilities."
    ),
    "PY-XSS-001": (
        "Cross-Site Scripting happens when user-controlled content is rendered "
        "in a web page without proper sanitization. Malicious scripts injected "
        "this way execute in victims' browsers with full access to cookies, "
        "session tokens, and page content. This enables session hijacking, "
        "credential theft, and phishing attacks that appear to come from your site."
    ),
    "PY-AUTH-001": (
        "Authentication weaknesses — such as hardcoded secrets, weak algorithms, "
        "or missing security flags — allow attackers to forge sessions, bypass "
        "login mechanisms, or impersonate users. Even a single misconfigured "
        "JWT secret or missing cookie flag can grant full administrative access "
        "to your application."
    ),
    "WEB-GENERIC": (
        "Security misconfigurations in HTTP headers, TLS settings, and server "
        "responses expose your application to various attacks. Missing security "
        "headers remove browser-enforced protections, while information disclosure "
        "helps attackers fingerprint your stack and plan targeted attacks. These "
        "issues are often chained together for larger, more impactful exploits."
    ),
    # ── Headers ──
    "HEADER-Strict-Transport-Security": (
        "Without HSTS, browsers may connect over plain HTTP even after visiting "
        "the HTTPS version. Attackers on the same network can intercept and modify "
        "this unencrypted traffic (SSL stripping), stealing credentials and session "
        "tokens transmitted in the clear."
    ),
    "HEADER-Content-Security-Policy": (
        "Without a Content Security Policy, browsers will execute any script "
        "injected into your pages. CSP acts as a whitelist telling browsers which "
        "sources of scripts, styles, and other resources are legitimate. Without "
        "it, a single XSS flaw becomes much more exploitable."
    ),
    "HEADER-X-Frame-Options": (
        "Without X-Frame-Options, your site can be embedded in an invisible "
        "iframe on an attacker's page. Users think they're clicking on the "
        "attacker's page, but their clicks are actually sent to your site — "
        "this is called clickjacking and can trick users into performing "
        "unintended actions."
    ),
    # ── SSL/TLS ──
    "TLS-OLD": (
        "TLS 1.0 and 1.1 have known cryptographic weaknesses that allow "
        "attackers to decrypt traffic using attacks like BEAST and POODLE. "
        "All major browsers have deprecated these versions. Using them puts "
        "all data transmitted between your server and clients at risk."
    ),
    "CERT-EXP": (
        "An expired or soon-to-expire SSL certificate will cause browsers to "
        "show security warnings, driving users away. Worse, if the certificate "
        "expires and isn't renewed, traffic may fall back to unencrypted HTTP, "
        "exposing all data in transit."
    ),
    # ── CORS ──
    "CORS-WILDCARD": (
        "A wildcard CORS origin (Access-Control-Allow-Origin: *) allows any "
        "website to make cross-origin requests to your API. If your API returns "
        "user-specific data, any malicious site can read it by making requests "
        "from the victim's browser with their cookies attached."
    ),
    # ── Exposure ──
    "EXPOSED-ENV": (
        "An exposed .env file reveals database credentials, API keys, secret "
        "tokens, and other configuration secrets. With these, attackers can "
        "directly access your database, third-party services, and internal "
        "systems without needing to exploit any other vulnerability."
    ),
    "EXPOSED-GIT": (
        "An exposed .git directory allows attackers to download your entire "
        "source code history, including configuration files, credentials, "
        "and internal comments. This provides a complete blueprint for "
        "finding and exploiting other vulnerabilities in your application."
    ),
    # ── Forms ──
    "FORM-HTTP": (
        "Forms that submit over HTTP send credentials and sensitive data in "
        "plain text. Anyone monitoring the network — on public WiFi, through "
        "a compromised router, or via ISP-level surveillance — can read "
        "usernames, passwords, and personal data as they travel across the wire."
    ),
    # ── Future: Encryption weaknesses ──
    "CRYPTO-WEAK-HASH": (
        "Weak hashing algorithms like MD5 and SHA-1 are vulnerable to collision "
        "attacks and can be brute-forced rapidly with modern hardware. Passwords "
        "hashed with these algorithms can be cracked in seconds using precomputed "
        "rainbow tables or GPU-accelerated attacks."
    ),
    "CRYPTO-HARDCODED-KEY": (
        "Hardcoded encryption keys in source code are accessible to anyone who "
        "can view the code — including in compiled binaries through decompilation. "
        "Once an attacker has the key, all data encrypted with it is compromised "
        "and cannot be re-secured without re-encrypting everything."
    ),
}


# ── Safeguard Checklists ─────────────────────────────────────────

SAFEGUARD_CHECKLISTS = {
    "PY-SQLI-001": [
        {"step": "Use parameterized queries or prepared statements for ALL database calls", "priority": "critical"},
        {"step": "Adopt an ORM (SQLAlchemy, Django ORM) to abstract raw SQL", "priority": "high"},
        {"step": "Validate and sanitize all user inputs with whitelists", "priority": "high"},
        {"step": "Use least-privilege database accounts (read-only where possible)", "priority": "medium"},
        {"step": "Enable WAF rules that detect SQL injection patterns", "priority": "medium"},
        {"step": "Set up query logging and anomaly detection", "priority": "low"},
    ],
    "PY-XSS-001": [
        {"step": "Enable auto-escaping in your template engine (Jinja2, React JSX)", "priority": "critical"},
        {"step": "Sanitize HTML with a whitelist library (DOMPurify, bleach)", "priority": "high"},
        {"step": "Deploy Content Security Policy headers", "priority": "high"},
        {"step": "Set HttpOnly + Secure flags on all session cookies", "priority": "high"},
        {"step": "Use Subresource Integrity (SRI) for external scripts", "priority": "medium"},
        {"step": "Validate all inputs server-side, not just client-side", "priority": "medium"},
    ],
    "PY-AUTH-001": [
        {"step": "Store secrets in environment variables, never in source code", "priority": "critical"},
        {"step": "Use strong password hashing (bcrypt/Argon2) with unique salts", "priority": "critical"},
        {"step": "Enable multi-factor authentication for admin/sensitive operations", "priority": "high"},
        {"step": "Use established auth libraries (OAuth 2.0, Passport.js)", "priority": "high"},
        {"step": "Implement account lockout after repeated failures", "priority": "medium"},
        {"step": "Log and monitor all authentication events", "priority": "medium"},
    ],
    "WEB-GENERIC": [
        {"step": "Add all recommended security headers (HSTS, CSP, X-Frame-Options)", "priority": "high"},
        {"step": "Enforce HTTPS everywhere with valid TLS 1.2+ certificates", "priority": "high"},
        {"step": "Remove server version headers and debug info", "priority": "medium"},
        {"step": "Restrict CORS to specific trusted origins", "priority": "medium"},
        {"step": "Disable unnecessary HTTP methods (TRACE, OPTIONS)", "priority": "low"},
        {"step": "Audit server config against CIS benchmarks regularly", "priority": "low"},
    ],
}


# ── Related Attack Techniques ─────────────────────────────────────

ATTACK_TECHNIQUES = {
    "PY-SQLI-001": [
        "UNION-based SQL Injection",
        "Blind Boolean-based Injection",
        "Time-based Blind Injection",
        "Error-based Injection",
        "Second-order Injection",
    ],
    "PY-XSS-001": [
        "Reflected XSS (via URL parameters)",
        "Stored XSS (persisted in database)",
        "DOM-based XSS (client-side manipulation)",
        "Mutation XSS (parser confusion)",
    ],
    "PY-AUTH-001": [
        "Credential Stuffing",
        "Session Fixation",
        "JWT Algorithm Confusion",
        "Password Spraying",
        "Token Forgery",
    ],
    "WEB-GENERIC": [
        "Clickjacking (UI Redressing)",
        "SSL Stripping (MITM)",
        "MIME Sniffing Exploitation",
        "Cross-Origin Data Theft",
    ],
}


@dataclass
class AIAnalysis:
    """Structured AI-generated threat analysis for a finding."""
    danger_rating: int                        # 1-10
    danger_label: str                         # "Critical Risk", etc.
    danger_emoji: str                         # 🔴, etc.
    danger_color: str                         # CSS color name
    exploitation_summary: str                 # How this vuln class is exploited
    impact_description: str                   # What damage it can cause
    fix_explanation: str                      # Why the suggested fix works
    safeguard_steps: List[Dict[str, str]]     # Prioritized checklist
    related_attacks: List[str]                # Named attack techniques

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        return {
            "danger_rating": self.danger_rating,
            "danger_label": self.danger_label,
            "danger_emoji": self.danger_emoji,
            "danger_color": self.danger_color,
            "exploitation_summary": self.exploitation_summary,
            "impact_description": self.impact_description,
            "fix_explanation": self.fix_explanation,
            "safeguard_steps": self.safeguard_steps,
            "related_attacks": self.related_attacks,
        }


def _cvss_to_danger(cvss_score: float) -> int:
    """Map CVSS score to danger level (1-10)."""
    if cvss_score >= 9.0:
        return 10
    elif cvss_score >= 8.0:
        return 9
    elif cvss_score >= 7.0:
        return 8
    elif cvss_score >= 6.0:
        return 7
    elif cvss_score >= 5.0:
        return 6
    elif cvss_score >= 4.0:
        return 5
    elif cvss_score >= 3.0:
        return 4
    elif cvss_score >= 2.0:
        return 3
    elif cvss_score >= 1.0:
        return 2
    return 1


def _severity_to_danger(severity: str) -> int:
    """Fallback: map severity string to danger level."""
    return {
        "critical": 9,
        "high": 7,
        "medium": 5,
        "low": 3,
        "info": 1,
    }.get(severity.lower(), 5)


def analyze_finding(
    finding_dict: Dict[str, Any],
    rule_id: str,
    severity: str = "medium"
) -> AIAnalysis:
    """Generate AI analysis for a single finding.

    Args:
        finding_dict: The finding data dict
        rule_id: Scanner rule ID (e.g., PY-SQLI-001)
        severity: Severity string for fallback danger calculation

    Returns:
        AIAnalysis with all threat intelligence fields
    """
    # Get intel from KB
    intel = get_intel(rule_id)

    # Calculate danger rating
    if intel and 'cvss_score' in intel:
        danger = _cvss_to_danger(intel['cvss_score'])
    else:
        danger = _severity_to_danger(severity)

    danger_info = DANGER_LEVELS.get(danger, DANGER_LEVELS[5])

    # Get exploitation summary (try specific rule_id, then fallback)
    exploitation = EXPLOITATION_SUMMARIES.get(
        rule_id,
        EXPLOITATION_SUMMARIES.get("WEB-GENERIC", "No exploitation data available for this vulnerability class.")
    )

    # Get impact from intel KB
    impact = (intel or {}).get('risk_impact', finding_dict.get('message', 'Potential security vulnerability detected.'))

    # Get fix explanation from the patch
    patch = finding_dict.get('patch')
    fix_explanation = ""
    if patch:
        fix_explanation = patch.get('explanation', patch.get('description', ''))
    elif intel:
        # Synthesize from remediation steps
        steps = intel.get('remediation_steps', [])
        if steps:
            fix_explanation = f"Primary fix: {steps[0]}. " + (f"Additionally: {steps[1]}" if len(steps) > 1 else "")

    # Get safeguard checklist (try specific, then fallback)
    safeguards = SAFEGUARD_CHECKLISTS.get(
        rule_id,
        SAFEGUARD_CHECKLISTS.get("WEB-GENERIC", [])
    )

    # Get related attack techniques
    attacks = ATTACK_TECHNIQUES.get(
        rule_id,
        ATTACK_TECHNIQUES.get("WEB-GENERIC", [])
    )

    return AIAnalysis(
        danger_rating=danger,
        danger_label=danger_info["label"],
        danger_emoji=danger_info["emoji"],
        danger_color=danger_info["color"],
        exploitation_summary=exploitation,
        impact_description=impact,
        fix_explanation=fix_explanation,
        safeguard_steps=safeguards,
        related_attacks=attacks,
    )


def enrich_finding_with_ai(finding_dict: Dict[str, Any], rule_id: str) -> Dict[str, Any]:
    """Enrich a finding dict with AI analysis.

    Adds an 'ai_analysis' key alongside the existing 'intel' key.

    Args:
        finding_dict: Finding dict (already enriched with intel)
        rule_id: Scanner rule ID

    Returns:
        Finding dict with added ai_analysis field
    """
    severity = finding_dict.get('severity', 'medium')
    analysis = analyze_finding(finding_dict, rule_id, severity)
    finding_dict['ai_analysis'] = analysis.to_dict()
    return finding_dict
