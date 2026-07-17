"""Security detection rules."""
from scanner.rules.sqli import SQLInjectionRule
from scanner.rules.xss import XSSRule
from scanner.rules.auth import AuthRule

RULES = [
    SQLInjectionRule,
    XSSRule,
    AuthRule,
]
