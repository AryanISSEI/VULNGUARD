"""SQL Injection detection and fix generation."""
import re
from pathlib import Path
from typing import List, Optional

from scanner.findings import Finding, Patch, Severity, Confidence, CodeLocation
from scanner.parsers.python import PythonParser, FastAPIAnalyzer


class SQLInjectionRule:
    """Detect SQL injection vulnerabilities in Python/FastAPI code."""

    RULE_ID = "PY-SQLI-001"
    RULE_NAME = "SQL Injection"

    # Patterns that indicate SQL string construction
    DANGEROUS_PATTERNS = [
        # f-strings with SQL keywords
        (r'f["\']\s*(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|AND|OR).*?\{[^}]+\}',
         "f-string interpolation", Severity.HIGH),
        # .format() with SQL
        (r'(?:SELECT|INSERT|UPDATE|DELETE).*\.format\s*\(',
         "format method", Severity.HIGH),
        # % formatting with SQL
        (r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*%\s*\(',
         "% formatting", Severity.HIGH),
        # + concatenation with SQL
        (r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*\+',
         "string concatenation", Severity.MEDIUM),
    ]

    def __init__(self):
        self.parser = PythonParser()

    def analyze(self, file_path: Path, source: Optional[str] = None) -> List[Finding]:
        """Analyze a file for SQL injection vulnerabilities."""
        findings = []

        node = self.parser.parse(file_path)
        if not node:
            return findings

        # Use FastAPI analyzer for route-aware detection
        analyzer = FastAPIAnalyzer(self.parser)

        # Find all SQL execute calls
        sql_calls = analyzer.find_sql_calls(node)

        for call in sql_calls:
            finding = self._analyze_call(call, file_path, source)
            if finding:
                findings.append(finding)

        # Also check for patterns in raw source as fallback
        if not findings and hasattr(node, 'find_sql_injection_candidates'):
            candidates = node.find_sql_injection_candidates()
            for candidate in candidates:
                finding = self._create_finding_from_candidate(
                    candidate, file_path, source
                )
                if finding:
                    findings.append(finding)

        return findings

    def _analyze_call(self, call: dict, file_path: Path, source: Optional[str]) -> Optional[Finding]:
        """Analyze a SQL execute call for vulnerabilities."""
        args_text = call.get('arguments', '')
        line_num = call.get('line', 1)
        source_code = call.get('source', '')

        # Check if using parameterized query already
        if self._is_parameterized(args_text):
            return None

        # Check for dangerous patterns
        dangerous_match = self._match_dangerous_pattern(args_text)
        if not dangerous_match:
            # Might still be vulnerable if variable passed
            if self._is_variable_only(args_text):
                dangerous_match = ("variable without parameters", Severity.MEDIUM)
            else:
                return None

        pattern_desc, severity = dangerous_match

        # Generate fix
        patch = self._generate_patch(source_code, args_text)

        # Calculate confidence based on context
        confidence = self._calculate_confidence(args_text)

        return Finding(
            id=f"SQLI-{file_path.stem}-{line_num}",
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            severity=severity,
            confidence=confidence,
            message=f"SQL injection via {pattern_desc}. User input flows directly into SQL query.",
            location=CodeLocation(
                file=file_path,
                line_start=line_num,
                line_end=line_num,
                column_start=call.get('column', 0),
                column_end=call.get('column', 0) + len(source_code)
            ),
            snippet=source_code,
            patch=patch
        )

    def _is_parameterized(self, args_text: str) -> bool:
        """Check if query uses parameterized style."""
        # Look for ? or %s placeholders followed by params tuple
        if re.search(r'["\'][^"\']*\?[^"\']*["\']\s*,\s*\(', args_text):
            return True
        if re.search(r'["\'][^"\']*%s[^"\']*["\']\s*,\s*\(', args_text):
            return True
        # Named parameters
        if re.search(r':\w+', args_text):
            return True
        return False

    def _match_dangerous_pattern(self, args_text: str) -> Optional[tuple]:
        """Check if arguments contain dangerous patterns."""
        for pattern, desc, severity in self.DANGEROUS_PATTERNS:
            if re.search(pattern, args_text, re.IGNORECASE):
                return (desc, severity)
        return None

    def _is_variable_only(self, args_text: str) -> bool:
        """Check if args is just a variable."""
        # Strip parens and whitespace, check if single identifier
        cleaned = args_text.strip('() \n\t')
        return re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', cleaned) is not None

    def _calculate_confidence(self, args_text: str) -> Confidence:
        """Calculate confidence in the fix."""
        # High confidence: simple f-string replacement
        if 'f"' in args_text or "f'" in args_text:
            # Check if multiple interpolations
            interpolations = len(re.findall(r'\{[^}]+\}', args_text))
            if interpolations == 1:
                return Confidence.HIGH
            elif interpolations <= 3:
                return Confidence.MEDIUM
            else:
                return Confidence.LOW

        # Medium: .format() or %
        if '.format(' in args_text or '%' in args_text:
            return Confidence.MEDIUM

        return Confidence.LOW

    def _generate_patch(self, original_code: str, args_text: str) -> Patch:
        """Generate a parameterized query fix."""

        # Extract the query and variables from f-string
        if 'f"' in args_text or "f'" in args_text:
            return self._fix_fstring(original_code, args_text)

        if '.format(' in args_text:
            return self._fix_format(original_code, args_text)

        if '%' in args_text:
            return self._fix_percent_format(original_code, args_text)

        # Fallback: variable replacement
        return self._fix_variable(original_code, args_text)

    def _fix_fstring(self, original_code: str, args_text: str) -> Patch:
        """Fix f-string SQL interpolation."""
        # Find all {var} patterns
        interpolations = re.findall(r'\{([^}]+)\}', args_text)

        if not interpolations:
            return None

        # Build parameterized query
        query_pattern = re.sub(r'\{[^}]+\}', '?', args_text)
        params = ', '.join(interpolations)

        # Extract the method call prefix (e.g., "cursor.execute")
        match = re.match(r'(\w+\.\w+)\s*\((.*)\)', original_code)
        if match:
            method = match.group(1)
            fixed = f'{method}({query_pattern}, ({params},))'
        else:
            fixed = original_code  # Fallback

        confidence = Confidence.HIGH if len(interpolations) == 1 else Confidence.MEDIUM

        return Patch(
            original_code=original_code,
            fixed_code=fixed,
            description="Use parameterized query with ? placeholders",
            confidence=confidence,
            explanation="Parameterized queries prevent SQL injection by separating code from data. "
                       "The database driver handles proper escaping."
        )

    def _fix_format(self, original_code: str, args_text: str) -> Patch:
        """Fix .format() SQL interpolation."""
        # Extract base string and format args
        match = re.match(r'(.+)\.format\s*\((.+)\)', args_text)
        if not match:
            return None

        base = match.group(1)
        format_args = match.group(2)

        # Replace {0} or {name} with ?
        query_pattern = re.sub(r'\{[^}]*\}', '?', base)
        fixed = f'{query_pattern}, ({format_args})'

        # Wrap in execute call
        execute_match = re.match(r'(\w+\.\w+)\s*\(', original_code)
        if execute_match:
            fixed = f'{execute_match.group(1)}({fixed})'

        return Patch(
            original_code=original_code,
            fixed_code=fixed,
            description="Replace .format() with parameterized query",
            confidence=Confidence.MEDIUM,
            explanation="Parameterized queries prevent SQL injection. "
                       "Pass values as a separate tuple parameter."
        )

    def _fix_percent_format(self, original_code: str, args_text: str) -> Patch:
        """Fix % formatting SQL interpolation."""
        match = re.match(r'(.+)%\s*(.+)', args_text)
        if not match:
            return None

        base = match.group(1)
        percent_args = match.group(2)

        # Replace %s with ?
        query_pattern = re.sub(r'%s', '?', base)
        fixed = f'{query_pattern}, {percent_args}'

        # Wrap in execute call
        execute_match = re.match(r'(\w+\.\w+)\s*\(', original_code)
        if execute_match:
            fixed = f'{execute_match.group(1)}({fixed})'

        return Patch(
            original_code=original_code,
            fixed_code=fixed,
            description="Replace % formatting with parameterized query",
            confidence=Confidence.MEDIUM,
            explanation="% formatting is vulnerable to SQL injection. "
                       "Use parameterized queries instead."
        )

    def _fix_variable(self, original_code: str, args_text: str) -> Patch:
        """Fix variable-only query."""
        var_name = args_text.strip('() \n\t')

        fixed = original_code.replace(
            f'({var_name})',
            f'(query, ({var_name},))'
        )

        # Need to add query definition - this is a placeholder
        # In practice, user needs to define the query with ? placeholders

        return Patch(
            original_code=original_code,
            fixed_code=f"# TODO: Define query with ? placeholders\n# query = \"SELECT * FROM users WHERE id = ?\"\n{fixed}",
            description="Use parameterized query with placeholders",
            confidence=Confidence.LOW,
            explanation="Variables passed directly to execute() must be wrapped in a tuple "
                       "with a parameterized query containing ? placeholders."
        )

    def _create_finding_from_candidate(self, candidate: dict, file_path: Path,
                                       source: Optional[str]) -> Finding:
        """Create finding from fallback candidate."""
        line_num = candidate.get('line', 1)
        text = candidate.get('text', '')

        # Generate a basic patch
        patch = Patch(
            original_code=text,
            fixed_code="# TODO: Convert to parameterized query\n# cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            description="Replace with parameterized query",
            confidence=Confidence.LOW,
            explanation="Use ? placeholders and pass values as a separate tuple parameter."
        )

        return Finding(
            id=f"SQLI-FALLBACK-{line_num}",
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            message="Possible SQL injection via string interpolation. Manual review required.",
            location=CodeLocation(
                file=file_path,
                line_start=line_num,
                line_end=line_num,
                column_start=0,
                column_end=len(text)
            ),
            snippet=text,
            patch=patch
        )
