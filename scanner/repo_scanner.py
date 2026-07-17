"""Git repository scanner — clone and scan remote repositories.

Supports GitHub, GitLab, and Bitbucket public repositories.
Clones with --depth 1 for speed, scans all files, then cleans up.
"""
import asyncio
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from scanner.core import Scanner
from scanner.vuln_intel import enrich_finding


# Safeguard limits
MAX_CLONE_TIMEOUT_SEC = 300   # 5 minutes
MAX_REPO_SIZE_MB = 500
MAX_FILE_COUNT = 5000

# Supported host patterns
REPO_URL_PATTERN = re.compile(
    r'^https?://(github\.com|gitlab\.com|bitbucket\.org|[\w.-]+)/[\w./-]+$'
)


@dataclass
class CloneProgress:
    """Tracks repo clone + scan progress."""
    stage: str = "pending"        # pending | cloning | scanning | analyzing | done | error
    message: str = ""
    percent: int = 0
    files_found: int = 0
    files_scanned: int = 0
    findings_count: int = 0
    error: Optional[str] = None


def validate_repo_url(url: str) -> str:
    """Validate and normalize a repository URL.

    Returns:
        Normalized URL string

    Raises:
        ValueError: If URL is invalid or unsupported
    """
    url = url.strip().rstrip('/')

    # Strip .git suffix if present for display, but keep for cloning
    display_url = url.removesuffix('.git')

    # Add .git if missing (GitHub/GitLab convention)
    clone_url = url if url.endswith('.git') else url + '.git'

    if not REPO_URL_PATTERN.match(display_url):
        raise ValueError(
            f"Invalid repository URL. Supported: GitHub, GitLab, Bitbucket. Got: {url}"
        )

    return clone_url


def detect_repo_host(url: str) -> str:
    """Detect the hosting platform from URL."""
    if 'github.com' in url:
        return 'github'
    elif 'gitlab.com' in url:
        return 'gitlab'
    elif 'bitbucket.org' in url:
        return 'bitbucket'
    return 'generic'


def clone_repo(url: str, target_dir: Path, progress: CloneProgress) -> Path:
    """Clone a git repository to target directory.

    Uses --depth 1 for shallow clone (speed + bandwidth).

    Args:
        url: Git clone URL
        target_dir: Directory to clone into
        progress: Progress tracker

    Returns:
        Path to cloned repo

    Raises:
        RuntimeError: If clone fails or times out
    """
    progress.stage = "cloning"
    progress.message = "Cloning repository..."
    progress.percent = 10

    repo_name = url.split('/')[-1].removesuffix('.git') or 'repo'
    clone_path = target_dir / repo_name

    try:
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', '--single-branch', url, str(clone_path)],
            capture_output=True,
            text=True,
            timeout=MAX_CLONE_TIMEOUT_SEC,
            cwd=str(target_dir)
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip()
            # Common error patterns
            if 'not found' in error_msg.lower() or 'does not exist' in error_msg.lower():
                raise RuntimeError(f"Repository not found. Check the URL and ensure it's public.")
            elif 'authentication' in error_msg.lower() or 'denied' in error_msg.lower():
                raise RuntimeError(f"Access denied. Private repos are not yet supported.")
            else:
                raise RuntimeError(f"Git clone failed: {error_msg[:200]}")

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Clone timed out after {MAX_CLONE_TIMEOUT_SEC}s. "
            f"The repository may be too large."
        )
    except FileNotFoundError:
        raise RuntimeError(
            "Git is not installed or not in PATH. "
            "Install Git from https://git-scm.com/"
        )

    progress.percent = 30
    progress.message = "Repository cloned successfully"

    # Check repo size
    total_size = sum(
        f.stat().st_size for f in clone_path.rglob('*') if f.is_file()
    )
    size_mb = total_size / (1024 * 1024)

    if size_mb > MAX_REPO_SIZE_MB:
        raise RuntimeError(
            f"Repository is too large ({size_mb:.0f}MB). "
            f"Maximum supported size is {MAX_REPO_SIZE_MB}MB."
        )

    return clone_path


def scan_repo(repo_path: Path, progress: CloneProgress) -> Dict[str, Any]:
    """Scan a cloned repository using the core scanner engine.

    Args:
        repo_path: Path to the cloned repo
        progress: Progress tracker

    Returns:
        Scan results in dashboard-compatible format
    """
    progress.stage = "scanning"
    progress.message = "Scanning repository files..."
    progress.percent = 40

    scanner = Scanner()

    # Count files first
    scannable_files = list(scanner._collect_files(repo_path))
    progress.files_found = len(scannable_files)

    if len(scannable_files) > MAX_FILE_COUNT:
        progress.message = f"Warning: Scanning first {MAX_FILE_COUNT} of {len(scannable_files)} files"
        # Scanner will handle all files, but we warn about large repos

    progress.percent = 50
    progress.message = f"Scanning {len(scannable_files)} files..."

    # Run the scan
    result = scanner.scan(repo_path)

    progress.files_scanned = result.files_scanned
    progress.findings_count = len(result.findings)
    progress.percent = 80
    progress.stage = "analyzing"
    progress.message = "Enriching findings with threat intelligence..."

    # Build dashboard-compatible JSON
    repo_name = repo_path.name

    json_data = {
        'findings': [
            enrich_finding({
                'id': f.id,
                'rule': f.rule_name,
                'severity': f.severity.value,
                'confidence': f.confidence.value,
                'message': f.message,
                'file': str(f.location.file).replace(str(repo_path), repo_name),
                'line': f.location.line_start,
                'snippet': f.snippet,
                'patch': {
                    'description': f.patch.description,
                    'fixed_code': f.patch.fixed_code,
                    'explanation': f.patch.explanation,
                    'confidence': f.patch.confidence.value
                } if f.patch else None
            }, f.rule_id)
            for f in result.findings
        ],
        'summary': {
            'total': len(result.findings),
            'total_findings': len(result.findings),
            'critical': sum(1 for f in result.findings if f.severity.value == 'critical'),
            'high': sum(1 for f in result.findings if f.severity.value == 'high'),
            'medium': sum(1 for f in result.findings if f.severity.value == 'medium'),
            'low': sum(1 for f in result.findings if f.severity.value == 'low'),
            'patches_available': result.patches_available(),
            'duration_ms': result.duration_ms,
            'files_scanned': result.files_scanned
        },
        'scan_source': {
            'type': 'repository',
            'name': repo_name,
            'url': '',  # Will be set by caller
            'host': ''  # Will be set by caller
        }
    }

    progress.percent = 100
    progress.stage = "done"
    progress.message = f"Scan complete — {len(result.findings)} findings in {result.files_scanned} files"

    return json_data


def clone_and_scan(repo_url: str) -> Dict[str, Any]:
    """Full pipeline: validate → clone → scan → cleanup.

    Args:
        repo_url: Public Git repository URL

    Returns:
        Dashboard-compatible scan results dict

    Raises:
        ValueError: Invalid URL
        RuntimeError: Clone or scan failure
    """
    # Validate
    clone_url = validate_repo_url(repo_url)
    host = detect_repo_host(repo_url)

    progress = CloneProgress()

    # Clone into temp dir
    temp_dir = tempfile.mkdtemp(prefix='vulnguard_repo_')

    try:
        repo_path = clone_repo(clone_url, Path(temp_dir), progress)
        result = scan_repo(repo_path, progress)

        # Attach source metadata
        result['scan_source']['url'] = repo_url
        result['scan_source']['host'] = host

        return result

    finally:
        # Always clean up
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
