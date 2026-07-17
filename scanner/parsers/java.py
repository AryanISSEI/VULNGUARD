"""Java parser using tree-sitter."""
from pathlib import Path
from typing import List, Dict, Any, Optional
import re

class JavaNode:
    """Wrapper for tree-sitter node."""
    def __init__(self, node, source: str, tree):
        self._node = node
        self.source = source
        self._tree = tree

    def text(self) -> str:
        return self.source[self._node.start_byte:self._node.end_byte]

    def type(self) -> str:
        return self._node.type

class JavaParser:
    """Parse Java files for security analysis."""
    def __init__(self):
        self._parser = None
        self._language = None
        self._init_tree_sitter()

    def _init_tree_sitter(self):
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_java
            self._language = Language(tree_sitter_java.language())
            self._parser = Parser(self._language)
        except ImportError:
            self._parser = None

    def parse(self, file_path: Path) -> Optional[JavaNode]:
        try:
            source = file_path.read_text(encoding='utf-8')
        except (UnicodeDecodeError, IOError):
            return None

        if self._parser:
            try:
                tree = self._parser.parse(source.encode('utf-8'))
                return JavaNode(tree.root_node, source, tree)
            except Exception:
                pass
        return None
