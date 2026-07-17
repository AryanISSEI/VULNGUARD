"""Python/FastAPI parser using tree-sitter."""
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import re


class PythonNode:
    """Wrapper for tree-sitter node."""
    def __init__(self, node, source: str, tree):
        self._node = node
        self.source = source
        self._tree = tree

    def text(self) -> str:
        return self.source[self._node.start_byte:self._node.end_byte]

    def type(self) -> str:
        return self._node.type

    def children(self) -> List["PythonNode"]:
        return [PythonNode(c, self.source, self._tree) for c in self._node.children]

    def child_by_type(self, node_type: str) -> Optional["PythonNode"]:
        for child in self._node.children:
            if child.type == node_type:
                return PythonNode(child, self.source, self._tree)
        return None

    def find_all(self, node_type: str) -> List["PythonNode"]:
        results = []
        def traverse(node):
            if node.type == node_type:
                results.append(PythonNode(node, self.source, self._tree))
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

    @property
    def start_column(self) -> int:
        return self._node.start_point[1]

    @property
    def end_column(self) -> int:
        return self._node.end_point[1]


class PythonParser:
    """Parse Python files for security analysis."""

    def __init__(self):
        self._parser = None
        self._language = None
        self._init_tree_sitter()

    def _init_tree_sitter(self):
        """Initialize tree-sitter with Python grammar."""
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_python

            self._language = Language(tree_sitter_python.language())
            self._parser = Parser(self._language)
        except ImportError:
            # Fallback: regex-based parsing for MVP if tree-sitter fails
            self._parser = None

    def parse(self, file_path: Path) -> Optional[PythonNode]:
        """Parse a Python file."""
        try:
            source = file_path.read_text(encoding='utf-8')
        except (UnicodeDecodeError, IOError):
            return None

        if self._parser:
            try:
                tree = self._parser.parse(source.encode('utf-8'))
                return PythonNode(tree.root_node, source, tree)
            except Exception:
                pass

        # Fallback: return a mock node with raw source
        return FallbackPythonNode(source, file_path)

    def parse_source(self, source: str) -> Optional[PythonNode]:
        """Parse source code string."""
        if self._parser:
            try:
                tree = self._parser.parse(source.encode('utf-8'))
                return PythonNode(tree.root_node, source, tree)
            except Exception:
                pass
        return None


class FallbackPythonNode:
    """Fallback parser using regex when tree-sitter unavailable."""

    SQL_PATTERNS = [
        # f"...{var}..."
        r'f["\'][^"\']*\{[^}]+\}[^"\']*["\']',
        # .format() calls
        r'\.format\s*\([^)]+\)',
        # % formatting
        r'["\'][^"\']*%s[^"\']*["\']\s*%',
    ]

    def __init__(self, source: str, file_path: Path):
        self.source = source
        self.file_path = file_path

    def find_sql_injection_candidates(self) -> List[Dict[str, Any]]:
        """Find potential SQL injection points using regex."""
        results = []
        lines = self.source.split('\n')

        for i, line in enumerate(lines, 1):
            # Check for execute/executemany calls
            if re.search(r'\.(execute|executemany)\s*\(', line):
                # Check if line or nearby lines have string interpolation
                context = '\n'.join(lines[max(0, i-3):i+1])

                for pattern in self.SQL_PATTERNS:
                    if re.search(pattern, context):
                        results.append({
                            'line': i,
                            'column': line.find('execute'),
                            'text': line.strip(),
                            'type': 'sql_injection_candidate'
                        })
                        break

        return results

    def find_dangerous_imports(self) -> List[Dict[str, Any]]:
        """Find dangerous imports (eval, exec, pickle, etc)."""
        results = []
        lines = self.source.split('\n')

        dangerous = ['eval', 'exec', 'pickle', 'yaml.load', 'subprocess.shell']

        for i, line in enumerate(lines, 1):
            for d in dangerous:
                if d in line:
                    results.append({
                        'line': i,
                        'text': line.strip(),
                        'type': f'dangerous_{d}'
                    })

        return results


class FastAPIAnalyzer:
    """Analyze FastAPI-specific patterns."""

    def __init__(self, parser: PythonParser):
        self.parser = parser

    def find_routes(self, node: PythonNode) -> List[Dict[str, Any]]:
        """Find all FastAPI route definitions."""
        routes = []

        # Look for @app.get/post/put/delete decorators
        decorators = node.find_all("decorator")

        for dec in decorators:
            text = dec.text()
            route_match = re.match(r'@\w+\.(get|post|put|delete|patch)\s*\(', text)
            if route_match:
                method = route_match.group(1).upper()

                # Find the function definition that follows
                func_node = self._find_next_function(dec)
                if func_node:
                    routes.append({
                        'method': method,
                        'decorator_line': dec.start_line,
                        'function_line': func_node.start_line,
                        'function_name': self._extract_function_name(func_node),
                        'parameters': self._extract_parameters(func_node),
                        'source': func_node.text()
                    })

        return routes

    def _find_next_function(self, node: PythonNode) -> Optional[PythonNode]:
        """Find the function definition following a decorator."""
        # In tree-sitter, decorators are siblings of function_definition
        parent = node._node.parent
        if not parent:
            return None

        children = list(parent.children)
        try:
            idx = children.index(node._node)
            for child in children[idx + 1:]:
                if child.type == "function_definition":
                    return PythonNode(child, node.source, node._tree)
        except ValueError:
            pass

        return None

    def _extract_function_name(self, func_node: PythonNode) -> str:
        """Extract function name from definition."""
        name_node = func_node.child_by_type("identifier")
        if name_node:
            return name_node.text()
        return "unknown"

    def _extract_parameters(self, func_node: PythonNode) -> List[Dict[str, str]]:
        """Extract parameter names and types from function."""
        params = []
        params_node = func_node.child_by_type("parameters")

        if params_node:
            for child in params_node.children():
                if child.type() in ["identifier", "typed_parameter"]:
                    text = child.text()
                    # Parse name: type
                    if ':' in text:
                        name, typ = text.split(':', 1)
                        params.append({'name': name.strip(), 'type': typ.strip()})
                    else:
                        params.append({'name': text, 'type': None})

        return params

    def find_sql_calls(self, node: PythonNode) -> List[Dict[str, Any]]:
        """Find database query calls that might be vulnerable."""
        calls = []

        # Find all call nodes
        call_nodes = node.find_all("call")

        for call in call_nodes:
            func_text = call.text()
            # Look for cursor.execute, db.execute, etc.
            if re.search(r'\.(execute|executemany|executescript)\s*\(', func_text):
                # Get arguments
                args_node = call.child_by_type("argument_list")
                if args_node:
                    args_text = args_node.text()
                    calls.append({
                        'line': call.start_line,
                        'column': call.start_column,
                        'function': func_text[:func_text.find('(')],
                        'arguments': args_text,
                        'source': call.text()
                    })

        return calls
