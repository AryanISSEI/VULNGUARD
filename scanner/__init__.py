"""Fix-First Vulnerability Scanner

A developer-first security scanner that generates fix-ready patches
instead of noisy reports.
"""

__version__ = "0.1.0"
__all__ = ["Scanner", "Finding", "Patch"]

from scanner.core import Scanner
from scanner.findings import Finding, Patch
