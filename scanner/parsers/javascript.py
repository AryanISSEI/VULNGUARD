"""JavaScript/React parser for security analysis."""
from pathlib import Path
from typing import List, Dict, Any, Optional
import re


class JavaScriptNode:
    """Wrapper for tree-sitter JS node."""

    def __init__(self, node, source: str, tree):
        self._node = node
        self.source = source
        self._tree = tree

    def text(self) -> str:
        return self.source[self._node.start_byte:self._node.end_byte]

    def type(self) -> str:
        return self._node.type

    def children(self) -> List["JavaScriptNode"]:
        return [JavaScriptNode(c, self.source, self._tree) for c in self._node.children]

    def find_all(self, node_type: str) -> List["JavaScriptNode"]:
        results = []
        def traverse(node):
            if node.type == node_type:
                results.append(JavaScriptNode(node, self.source, self._tree))
            for child in node.children:
                traverse(child)
        traverse(self._node)
        return results

    @property
    def start_line(self) -> int:
        return self._node.start_point[0] + 1

    @property
    def end_line(self) -> int:
        return self._node.end_point[0] + 1


class JavaScriptParser:
    """Parse JavaScript/TypeScript/JSX files."""

    def __init__(self):
        self._parser = None
        self._init_tree_sitter()

    def _init_tree_sitter(self):
        """Initialize tree-sitter with JS/TS grammars."""
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_javascript

            self._language = Language(tree_sitter_javascript.language())
            self._parser = Parser(self._language)
        except ImportError:
            self._parser = None

    def parse(self, file_path: Path) -> Optional[JavaScriptNode]:
        """Parse a JS/TS file."""
        try:
            source = file_path.read_text(encoding='utf-8')
        except (UnicodeDecodeError, IOError):
            return None

        if self._parser:
            try:
                tree = self._parser.parse(source.encode('utf-8'))
                return JavaScriptNode(tree.root_node, source, tree)
            except Exception:
                pass

        return FallbackJavaScriptNode(source, file_path)


class FallbackJavaScriptNode:
    """Fallback regex-based parser."""

    def __init__(self, source: str, file_path: Path):
        self.source = source
        self.file_path = file_path

    def find_dangerous_html(self) -> List[Dict[str, Any]]:
        """Find dangerouslySetInnerHTML usage."""
        results = []
        lines = self.source.split('\n')

        for i, line in enumerate(lines, 1):
            if 'dangerouslySetInnerHTML' in line:
                results.append({
                    'line': i,
                    'text': line.strip(),
                    'type': 'dangerous_inner_html'
                })

        return results

    def find_eval_usage(self) -> List[Dict[str, Any]]:
        """Find eval() and Function() calls."""
        results = []
        lines = self.source.split('\n')

        for i, line in enumerate(lines, 1):
            # eval() calls
            if re.search(r'(?<!\w)eval\s*\(', line):
                results.append({
                    'line': i,
                    'text': line.strip(),
                    'type': 'eval_usage'
                })
            # new Function()
            if re.search(r'new\s+Function\s*\(', line):
                results.append({
                    'line': i,
                    'text': line.strip(),
                    'type': 'function_constructor'
                })

        return results

    def find_unsafe_jquery(self) -> List[Dict[str, Any]]:
        """Find unsafe jQuery patterns (html(), append(), etc)."""
        results = []
        lines = self.source.split('\n')

        unsafe_methods = ['.html(', '.append(', '.prepend(', '.replaceWith(', '.insertBefore(', '.insertAfter(']

        for i, line in enumerate(lines, 1):
            for method in unsafe_methods:
                if method in line:
                    results.append({
                        'line': i,
                        'text': line.strip(),
                        'type': f'unsafe_jquery_{method[1:-1]}'
                    })

        return results

    def find_fetch_without_csrf(self) -> List[Dict[str, Any]]:
        """Find fetch/XHR calls that might need CSRF tokens."""
        results = []
        lines = self.source.split('\n')

        for i, line in enumerate(lines, 1):
            # POST/PUT/DELETE fetch without CSRF header
            if re.search(r'fetch\s*\(', line):
                context = '\n'.join(lines[max(0, i-5):i+5])
                if re.search(r'method\s*:\s*[\'"]POST|[\'"]PUT|[\'"]DELETE', context):
                    if 'X-CSRF' not in context and 'csrf' not in context.lower():
                        results.append({
                            'line': i,
                            'text': line.strip(),
                            'type': 'possible_missing_csrf'
                        })

        return results


class ReactAnalyzer:
    """Analyze React-specific security patterns."""

    XSS_PROP_PATTERNS = {
        'dangerouslySetInnerHTML': {
            'severity': 'high',
            'fix_template': "// Replace with: {content} or sanitize with DOMPurify"
        }
    }

    def __init__(self, parser: JavaScriptParser):
        self.parser = parser

    def find_xss_vectors(self, node: JavaScriptNode) -> List[Dict[str, Any]]:
        """Find potential XSS vectors in React components."""
        vectors = []

        # Find JSX attributes
        jsx_attrs = node.find_all("jsx_attribute")

        for attr in jsx_attrs:
            attr_name = attr.text().split('=')[0] if '=' in attr.text() else attr.text()

            if attr_name in self.XSS_PROP_PATTERNS:
                config = self.XSS_PROP_PATTERNS[attr_name]
                vectors.append({
                    'line': attr.start_line,
                    'type': 'xss_dangerous_prop',
                    'prop': attr_name,
                    'severity': config['severity'],
                    'source': attr.text()
                })

        return vectors

    def find_unsanitized_inputs(self, node: JavaScriptNode) -> List[Dict[str, Any]]:
        """Find user inputs used without sanitization."""
        issues = []

        # Find window.location, document.URL, etc. usage
        dangerous_sources = [
            r'window\.location\.(href|search|hash)',
            r'document\.URL',
            r'document\.referrer',
            r'localStorage\.(getItem|\[)',
            r'sessionStorage\.(getItem|\[)'
        ]

        source_text = node.text()
        lines = source_text.split('\n')

        for i, line in enumerate(lines, 1):
            for pattern in dangerous_sources:
                if re.search(pattern, line):
                    # Check if used in dangerous sink (innerHTML, eval, etc)
                    if any(sink in line for sink in ['innerHTML', 'eval(', 'document.write']):
                        issues.append({
                            'line': i,
                            'type': 'unsanitized_source_in_sink',
                            'text': line.strip()
                        })

        return issues
