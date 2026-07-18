"""Encryption vulnerability scanner (scaffold).

Future module for detecting weak encryption patterns in source code:
- Weak hashing algorithms (MD5, SHA1 for security purposes)
- Hardcoded encryption/API keys
- Insecure random number generation (random instead of secrets)
- Weak cipher modes (ECB mode)
- Missing salt in password hashing
- Deprecated TLS/SSL usage in code

STATUS: Scaffold only — detection rules are not yet implemented.
See TODO markers for implementation guidance.
"""

import re
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

# Import core scanner models
from scanner.findings import Finding, CodeLocation, Severity, Confidence, Patch

# Import report encryption functions
from scanner.encryption.report_encryption import encrypt_report, decrypt_for_ai


class EncryptionScanner:
    """Scanner for cryptographic weaknesses in source code."""

    # Rule IDs for the encryption module
    RULES = {
        "CRYPTO-WEAK-HASH":       {"name": "Weak Hashing Algorithm", "severity": Severity.HIGH},
        "CRYPTO-HARDCODED-KEY":   {"name": "Hardcoded Encryption Key", "severity": Severity.CRITICAL},
        "CRYPTO-INSECURE-RANDOM": {"name": "Insecure Random Number Generator", "severity": Severity.MEDIUM},
    }

    # Patterns to detect 
    WEAK_HASH_PATTERNS = [
        (r'hashlib\.md5', "MD5 is cryptographically broken."),
        (r'hashlib\.sha1', "SHA-1 is cryptographically weak and deprecated."),
        (r'MD5\.new', "MD5 is cryptographically broken."),
        (r'SHA\.new', "SHA-1 is cryptographically weak and deprecated."),
        (r'crypto\.createHash\([\'"]md5[\'"]\)', "MD5 is cryptographically broken."),
        (r'crypto\.createHash\([\'"]sha1[\'"]\)', "SHA-1 is cryptographically weak and deprecated."),
        (r'MessageDigest\.getInstance\("MD5"\)', "MD5 is cryptographically broken."),
        (r'MessageDigest\.getInstance\("SHA-1"\)', "SHA-1 is cryptographically weak and deprecated."),
    ]

    HARDCODED_KEY_PATTERNS = [
        (r'(?:encryption|secret|api|auth)_?key\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded encryption/API key detected."),
        (r'(?:AES|DES|RSA)\.new\(\s*b?["\'][^"\']+["\']', "Hardcoded key used in cipher initialization."),
        (r'PRIVATE_KEY\s*=\s*["\'][^"\']+["\']', "Hardcoded private key detected."),
    ]

    INSECURE_RANDOM_PATTERNS = [
        (r'random\.random\(\)', "Standard random is not cryptographically secure. Use secrets module."),
        (r'random\.randint\(', "Standard random is not cryptographically secure. Use secrets module."),
        (r'random\.choice\(', "Standard random is not cryptographically secure. Use secrets module."),
        (r'Math\.random\(\)', "Math.random is not cryptographically secure. Use crypto.getRandomValues()."),
        (r'java\.util\.Random', "java.util.Random is not cryptographically secure. Use SecureRandom."),
    ]

    def __init__(self):
        """Initialize the encryption scanner."""
        self.findings: List[Finding] = []
        
        # Pre-compile regexes
        self.compiled_hashes = [(re.compile(p), m) for p, m in self.WEAK_HASH_PATTERNS]
        self.compiled_keys = [(re.compile(p), m) for p, m in self.HARDCODED_KEY_PATTERNS]
        self.compiled_random = [(re.compile(p), m) for p, m in self.INSECURE_RANDOM_PATTERNS]

    def analyze(self, file_path: Path, source: Optional[str] = None) -> List[Finding]:
        """Analyze a file for encryption weaknesses. This matches the core rule interface.

        Args:
            file_path: Path to the source file
            source: Optional pre-read source content

        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            if source is None:
                source = file_path.read_text(encoding='utf-8', errors='ignore')
        except IOError:
            return findings

        lines = source.splitlines()
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            # Check for weak hashes
            for regex, message in self.compiled_hashes:
                match = regex.search(line)
                if match:
                    rule_info = self.RULES["CRYPTO-WEAK-HASH"]
                    findings.append(self._create_finding(
                        "CRYPTO-WEAK-HASH", rule_info, message, file_path, line_num, line, match
                    ))

            # Check for hardcoded keys
            for regex, message in self.compiled_keys:
                match = regex.search(line)
                if match:
                    rule_info = self.RULES["CRYPTO-HARDCODED-KEY"]
                    findings.append(self._create_finding(
                        "CRYPTO-HARDCODED-KEY", rule_info, message, file_path, line_num, line, match
                    ))

            # Check for insecure randomness
            for regex, message in self.compiled_random:
                match = regex.search(line)
                if match:
                    rule_info = self.RULES["CRYPTO-INSECURE-RANDOM"]
                    findings.append(self._create_finding(
                        "CRYPTO-INSECURE-RANDOM", rule_info, message, file_path, line_num, line, match
                    ))

        return findings
        
    def _create_finding(self, rule_id: str, rule_info: dict, message: str, 
                        file_path: Path, line_num: int, line_content: str, match: re.Match) -> Finding:
        """Helper to construct a core Finding object."""
        return Finding(
            id=f"{rule_id}-{hash(f'{file_path}:{line_num}') % 10000}",
            rule_id=rule_id,
            rule_name=rule_info["name"],
            severity=rule_info["severity"],
            confidence=Confidence.HIGH,
            message=message,
            location=CodeLocation(
                file=file_path,
                line_start=line_num,
                line_end=line_num,
                column_start=match.start(),
                column_end=match.end()
            ),
            snippet=line_content.strip(),
            patch=self._generate_patch(rule_id, line_content.strip(), match)
        )

    def _generate_patch(self, rule_id: str, original_code: str, match: re.Match) -> Optional[Patch]:
        """Generate a fix for the identified vulnerability."""
        matched_str = match.group(0)
        
        if rule_id == "CRYPTO-WEAK-HASH":
            fixed_code = original_code
            if "md5" in matched_str.lower() or "sha1" in matched_str.lower() or "sha" in matched_str.lower():
                fixed_code = original_code.replace("md5", "sha256").replace("MD5", "SHA256").replace("sha1", "sha256").replace("SHA-1", "SHA-256").replace("SHA", "SHA256")
            
            return Patch(
                original_code=original_code,
                fixed_code=fixed_code,
                description="Upgrade to a secure hashing algorithm (SHA-256).",
                explanation="MD5 and SHA-1 are cryptographically broken. Use SHA-256 or higher for security purposes.",
                confidence=Confidence.MEDIUM
            )
            
        elif rule_id == "CRYPTO-INSECURE-RANDOM":
            fixed_code = original_code
            if "random.random()" in matched_str:
                fixed_code = original_code.replace("random.random()", "secrets.SystemRandom().random()")
            elif "random.randint(" in matched_str:
                fixed_code = original_code.replace("random.randint(", "secrets.SystemRandom().randint(")
            elif "random.choice(" in matched_str:
                fixed_code = original_code.replace("random.choice(", "secrets.SystemRandom().choice(")
            elif "Math.random()" in matched_str:
                fixed_code = original_code.replace("Math.random()", "(crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296)")
            elif "java.util.Random" in matched_str:
                fixed_code = original_code.replace("java.util.Random", "java.security.SecureRandom")
                
            return Patch(
                original_code=original_code,
                fixed_code=fixed_code,
                description="Use a cryptographically secure random number generator.",
                explanation="Standard PRNGs like 'random' or 'Math.random' are predictable. Secure PRNGs must be used for secrets.",
                confidence=Confidence.MEDIUM
            )
            
        elif rule_id == "CRYPTO-HARDCODED-KEY":
            fixed_code = original_code
            if "=" in matched_str:
                var_name = matched_str.split("=")[0].strip()
                fixed_code = f"{var_name} = os.environ.get('{var_name.upper()}')"
            
            return Patch(
                original_code=original_code,
                fixed_code=fixed_code,
                description="Load secrets from environment variables instead of hardcoding.",
                explanation="Hardcoded secrets can be easily extracted from source code. Load them dynamically at runtime.",
                confidence=Confidence.LOW
            )
            
        return None

