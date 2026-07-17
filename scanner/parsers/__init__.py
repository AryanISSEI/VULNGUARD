"""Language parsers using tree-sitter."""
from scanner.parsers.python import PythonParser
from scanner.parsers.javascript import JavaScriptParser

PARSERS = {
    ".py": PythonParser,
    ".js": JavaScriptParser,
    ".jsx": JavaScriptParser,
    ".ts": JavaScriptParser,
    ".tsx": JavaScriptParser,
}


def get_parser(file_path):
    from pathlib import Path
    ext = Path(file_path).suffix
    parser_class = PARSERS.get(ext)
    if parser_class:
        return parser_class()
    return None
