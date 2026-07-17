"""XSS detection and fix generation for React/JavaScript."""
import re
from pathlib import Path
from typing import List, Optional

from scanner.findings import Finding, Patch, Severity, Confidence, CodeLocation
from scanner.parsers.javascript import JavaScriptParser, ReactAnalyzer


class XSSRule:
    """Detect XSS vulnerabilities in React/JavaScript code."""

    RULE_ID = "JS-XSS-001"
    RULE_NAME = "Cross-Site Scripting (XSS)"

    # Dangerous patterns and their fixes
    DANGEROUS_PATTERNS = {
        "dangerouslySetInnerHTML": {
            "severity": Severity.HIGH,
            "message": "Using dangerouslySetInnerHTML can lead to XSS if content is not sanitized",
            "fix_strategy": "dompurify",
            "confidence": Confidence.HIGH
        },
        "eval": {
            "severity": Severity.CRITICAL,
            "message": "eval() executes arbitrary code and is extremely dangerous",
            "fix_strategy": "remove",
            "confidence": Confidence.HIGH
        },
        "document.write": {
            "severity": Severity.HIGH,
            "message": "document.write() can execute scripts and is unsafe",
            "fix_strategy": "dom_textcontent",
            "confidence": Confidence.HIGH
        },
        "innerHTML": {
            "severity": Severity.HIGH,
            "message": "innerHTML assignment can lead to XSS if content is not sanitized",
            "fix_strategy": "textcontent_or_sanitize",
            "confidence": Confidence.MEDIUM
        }
    }

    def __init__(self):
        self.parser = JavaScriptParser()

    def analyze(self, file_path: Path, source: Optional[str] = None) -> List[Finding]:
        """Analyze file for XSS vulnerabilities."""
        findings = []

        if file_path.suffix not in ['.js', '.jsx', '.ts', '.tsx']:
            return findings

        if source is None:
            try:
                source = file_path.read_text(encoding='utf-8')
            except (UnicodeDecodeError, IOError):
                return findings

        node = self.parser.parse(file_path)
        if not node:
            return findings

        # Check for React-specific patterns
        if self._is_react_file(file_path, source):
            analyzer = ReactAnalyzer(self.parser)
            react_findings = self._analyze_react(analyzer, node, file_path, source)
            findings.extend(react_findings)

        # Check for generic JS patterns
        generic_findings = self._analyze_javascript(node, file_path, source)
        findings.extend(generic_findings)

        return findings

    def _is_react_file(self, file_path: Path, source: str) -> bool:
        """Check if file is a React component."""
        return (
            "import React" in source or
            "from 'react'" in source or
            "from \"react\"" in source or
            file_path.suffix in ['.jsx', '.tsx']
        )

    def _analyze_react(self, analyzer: ReactAnalyzer, node, file_path: Path,
                       source: str) -> List[Finding]:
        """Analyze React-specific XSS vectors."""
        findings = []

        # Find dangerouslySetInnerHTML
        vectors = analyzer.find_xss_vectors(node)
        for vector in vectors:
            finding = self._create_react_finding(vector, file_path, source)
            if finding:
                findings.append(finding)

        # Find unsanitized inputs
        inputs = analyzer.find_unsanitized_inputs(node)
        for inp in inputs:
            finding = self._create_input_finding(inp, file_path, source)
            if finding:
                findings.append(finding)

        return findings

    def _analyze_javascript(self, node, file_path: Path, source: str) -> List[Finding]:
        """Analyze generic JavaScript for XSS."""
        findings = []
        lines = source.split('\n')

        for i, line in enumerate(lines, 1):
            findings.extend(self._check_line(line, i, file_path))

        return findings

    def _check_line(self, line: str, line_num: int, file_path: Path) -> List[Finding]:
        """Check a single line for XSS patterns."""
        findings = []

        for pattern_name, config in self.DANGEROUS_PATTERNS.items():
            if pattern_name == "eval":
                # Special handling for eval
                if re.search(r'(?<!\w)eval\s*\(', line):
                    finding = self._create_eval_finding(line, line_num, file_path)
                    findings.append(finding)
            elif pattern_name == "innerHTML":
                # Check for .innerHTML =
                if re.search(r'\.innerHTML\s*=', line):
                    finding = self._create_innerhtml_finding(line, line_num, file_path)
                    findings.append(finding)
            elif pattern_name == "document.write":
                if re.search(r'document\.write\s*\(', line):
                    finding = self._create_docwrite_finding(line, line_num, file_path)
                    findings.append(finding)

        return findings

    def _create_react_finding(self, vector: dict, file_path: Path, source: str) -> Finding:
        """Create finding for React XSS vector."""
        line = vector.get('line', 1)
        prop = vector.get('prop', '')
        snippet = vector.get('source', '')

        config = self.DANGEROUS_PATTERNS.get(prop, {})

        # Generate fix
        patch = self._generate_react_fix(prop, snippet, source)

        return Finding(
            id=f"XSS-REACT-{file_path.stem}-{line}",
            rule_id=self.RULE_ID,
            rule_name=f"{self.RULE_NAME} - {prop}",
            severity=config.get('severity', Severity.HIGH),
            confidence=config.get('confidence', Confidence.HIGH),
            message=config.get('message', 'XSS vulnerability detected'),
            location=CodeLocation(
                file=file_path,
                line_start=line,
                line_end=line,
                column_start=0,
                column_end=len(snippet)
            ),
            snippet=snippet,
            patch=patch
        )

    def _create_input_finding(self, inp: dict, file_path: Path, source: str) -> Finding:
        """Create finding for unsanitized input."""
        line = inp.get('line', 1)
        snippet = inp.get('text', '')

        return Finding(
            id=f"XSS-INPUT-{file_path.stem}-{line}",
            rule_id=self.RULE_ID,
            rule_name=f"{self.RULE_NAME} - Unsanitized Source",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            message="User-controlled input flows to a dangerous sink without sanitization",
            location=CodeLocation(
                file=file_path,
                line_start=line,
                line_end=line,
                column_start=0,
                column_end=len(snippet)
            ),
            snippet=snippet,
            patch=self._generate_input_fix(snippet)
        )

    def _create_eval_finding(self, line: str, line_num: int, file_path: Path) -> Finding:
        """Create finding for eval() usage."""
        # Extract what's being eval'd
        match = re.search(r'eval\s*\((.+?)\)', line)
        eval_content = match.group(1) if match else "..."

        fixed = f"// WARNING: eval() removed. Use safe alternative.\n// Original: {line.strip()}"

        patch = Patch(
            original_code=line.strip(),
            fixed_code=fixed,
            description="Remove eval() - use JSON.parse() for JSON, or other safe alternatives",
            confidence=Confidence.HIGH,
            explanation="eval() executes arbitrary code. For JSON parsing, use JSON.parse(). "
                       "For dynamic code, use safer patterns like Function constructor with validation."
        )

        return Finding(
            id=f"XSS-EVAL-{file_path.stem}-{line_num}",
            rule_id=self.RULE_ID,
            rule_name=f"{self.RULE_NAME} - eval()",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            message="eval() executes arbitrary code and enables code injection attacks",
            location=CodeLocation(
                file=file_path,
                line_start=line_num,
                line_end=line_num,
                column_start=line.find('eval'),
                column_end=line.find('eval') + 4
            ),
            snippet=line.strip(),
            patch=patch
        )

    def _create_innerhtml_finding(self, line: str, line_num: int, file_path: Path) -> Finding:
        """Create finding for innerHTML usage."""
        # Extract the assignment
        match = re.search(r'(.+\.innerHTML)\s*=\s*(.+)', line)
        if match:
            target = match.group(1)
            value = match.group(2)
        else:
            target = "element.innerHTML"
            value = "..."

        fixed = f"{target.replace('.innerHTML', '.textContent')} = {value}"

        patch = Patch(
            original_code=line.strip(),
            fixed_code=fixed,
            description="Use textContent instead of innerHTML (or sanitize with DOMPurify)",
            confidence=Confidence.MEDIUM,
            explanation="textContent doesn't parse HTML, preventing XSS. "
                       "If you need HTML, use DOMPurify.sanitize() first."
        )

        return Finding(
            id=f"XSS-INNERHTML-{file_path.stem}-{line_num}",
            rule_id=self.RULE_ID,
            rule_name=f"{self.RULE_NAME} - innerHTML",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            message="innerHTML can execute malicious scripts if content is attacker-controlled",
            location=CodeLocation(
                file=file_path,
                line_start=line_num,
                line_end=line_num,
                column_start=line.find('innerHTML'),
                column_end=line.find('innerHTML') + 9
            ),
            snippet=line.strip(),
            patch=patch
        )

    def _create_docwrite_finding(self, line: str, line_num: int, file_path: Path) -> Finding:
        """Create finding for document.write usage."""
        fixed = "// document.write removed - use DOM methods instead\n" + line.replace('document.write', '// document.write')

        patch = Patch(
            original_code=line.strip(),
            fixed_code=fixed,
            description="Replace document.write with safe DOM manipulation",
            confidence=Confidence.HIGH,
            explanation="document.write() can execute scripts and is deprecated. "
                       "Use document.createElement() and appendChild() instead."
        )

        return Finding(
            id=f"XSS-DOCWRITE-{file_path.stem}-{line_num}",
            rule_id=self.RULE_ID,
            rule_name=f"{self.RULE_NAME} - document.write",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            message="document.write() can execute scripts and interferes with document lifecycle",
            location=CodeLocation(
                file=file_path,
                line_start=line_num,
                line_end=line_num,
                column_start=line.find('document.write'),
                column_end=line.find('document.write') + 14
            ),
            snippet=line.strip(),
            patch=patch
        )

    def _generate_react_fix(self, prop: str, snippet: str, source: str) -> Patch:
        """Generate fix for React XSS pattern."""
        if prop == "dangerouslySetInnerHTML":
            # Extract the __html value
            match = re.search(r'__html:\s*(.+?)(?:\s*[,}])', snippet)
            if match:
                content = match.group(1).strip()
                fixed = f"// Use DOMPurify before rendering:\n// const clean = DOMPurify.sanitize({content});\n<div>{{clean}}</div>"
            else:
                fixed = "// Remove dangerouslySetInnerHTML, use DOMPurify + JSX instead"

            return Patch(
                original_code=snippet,
                fixed_code=fixed,
                description="Sanitize HTML with DOMPurify before rendering",
                confidence=Confidence.HIGH,
                explanation="Install dompurify (npm install dompurify), import it, "
                           "and sanitize HTML content before using in JSX."
            )

        return None

    def _generate_input_fix(self, snippet: str) -> Patch:
        """Generate fix for unsanitized input."""
        return Patch(
            original_code=snippet,
            fixed_code="// TODO: Validate and sanitize user input before using\n" + snippet,
            description="Add input validation and sanitization",
            confidence=Confidence.LOW,
            explanation="User input should be validated (type checking) and sanitized "
                       "(encoding special characters) before use."
        )
