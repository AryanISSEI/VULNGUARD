"""Command-line interface for the vulnerability scanner."""
import argparse
import json
import sys
import asyncio
from pathlib import Path
from typing import Optional

from scanner.core import Scanner, ScannerConfig
from scanner.findings import Severity
from scanner.web_scanner import WebSecurityScanner, HTMLFileScanner, WebFinding


def scan_local_files(args) -> int:
    """Scan local files for vulnerabilities."""
    # Load configuration
    config = ScannerConfig()
    if args.config:
        config = ScannerConfig.from_file(args.config)

    # Override with CLI args
    fail_on = args.fail_on or config.fail_on

    # Initialize scanner
    scanner = Scanner(fail_on=fail_on)

    # Run scan
    if not args.quiet:
        print(f"🔍 Scanning {args.path}...")

    result = scanner.scan(args.path)

    # Generate summary
    if not args.quiet:
        print()
        print(scanner.generate_summary(result))

    # Export SARIF
    if args.sarif:
        sarif_data = result.to_sarif()
        with open(args.sarif, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        if not args.quiet:
            print(f"\nSARIF report exported to: {args.sarif}")

    # Export JSON
    if args.json:
        json_data = {
            'findings': [
                {
                    'id': f.id,
                    'rule': f.rule_name,
                    'severity': f.severity.value,
                    'confidence': f.confidence.value,
                    'message': f.message,
                    'file': str(f.location.file),
                    'line': f.location.line_start,
                    'snippet': f.snippet,
                    'patch': {
                        'description': f.patch.description,
                        'fixed_code': f.patch.fixed_code,
                        'explanation': f.patch.explanation,
                        'confidence': f.patch.confidence.value
                    } if f.patch else None
                }
                for f in result.findings
            ],
            'summary': {
                'total': len(result.findings),
                'critical': sum(1 for f in result.findings if f.severity.value == 'critical'),
                'high': sum(1 for f in result.findings if f.severity.value == 'high'),
                'medium': sum(1 for f in result.findings if f.severity.value == 'medium'),
                'low': sum(1 for f in result.findings if f.severity.value == 'low'),
                'patches_available': result.patches_available(),
                'duration_ms': result.duration_ms,
                'files_scanned': result.files_scanned
            }
        }
        with open(args.json, 'w') as f:
            json.dump(json_data, f, indent=2)
        if not args.quiet:
            print(f"JSON report exported to: {args.json}")

    # Export patches
    if args.patches:
        scanner.export_patches(result, args.patches)
        if not args.quiet:
            print(f"Patches exported to: {args.patches}")

    # Apply fixes (with confirmation)
    if args.apply_fixes:
        applied = 0
        skipped = 0

        for finding in result.findings:
            if finding.patch and finding.patch.confidence.value == 'high':
                try:
                    file_path = finding.location.file
                    with open(file_path, 'r') as f:
                        content = f.read()

                    if finding.patch.original_code in content:
                        new_content = content.replace(
                            finding.patch.original_code,
                            finding.patch.fixed_code,
                            1
                        )
                        with open(file_path, 'w') as f:
                            f.write(new_content)
                        applied += 1
                    else:
                        skipped += 1
                except Exception as e:
                    if not args.quiet:
                        print(f"  Could not apply fix for {finding.id}: {e}")
                    skipped += 1
            else:
                skipped += 1

        if not args.quiet:
            print(f"\nFixes applied: {applied}, Skipped: {skipped}")

    # Exit with appropriate code
    if scanner.should_fail_build(result):
        if not args.quiet:
            print("\n❌ Build failed due to security issues.")
        return 1
    else:
        return 0


async def scan_website_async(url: str, args) -> int:
    """Scan a website for vulnerabilities."""
    scanner = WebSecurityScanner()

    print(f"Scanning website: {url}")
    print("-" * 60)

    result = await scanner.scan_url(url)

    # Print findings
    if result['findings']:
        print(f"\n⚠️  Found {len(result['findings'])} issues:\n")

        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        by_severity = {s: [] for s in severity_order}

        for f in result['findings']:
            sev = f['severity']
            if sev in by_severity:
                by_severity[sev].append(f)

        for severity in severity_order:
            findings = by_severity[severity]
            if findings:
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}[severity]
                print(f"\n{emoji} {severity.upper()} ({len(findings)})")
                print("-" * 40)

                for f in findings:
                    print(f"\n  📌 {f['rule_name']}")
                    print(f"     {f['message']}")
                    print(f"     URL: {f['url']}")
                    print(f"     Fix: {f['remediation']}")
    else:
        print("\n✅ No security issues found!")

    # Print summary
    summary = result['summary']
    print(f"\n{'=' * 60}")
    print(f"SUMMARY: {summary['critical']} critical, {summary['high']} high, "
          f"{summary['medium']} medium, {summary['low']} low, {summary['info']} info")
    print(f"{'=' * 60}")

    # Export if requested
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\n📄 Report saved to: {args.json}")

    # Return exit code
    if summary['critical'] > 0 or summary['high'] > 0:
        print("\n❌ Scan failed due to critical/high severity issues.")
        return 1
    return 0


def main():
    import sys
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass
    if hasattr(sys.stderr, 'reconfigure'):
        try:
            sys.stderr.reconfigure(encoding='utf-8')
        except Exception:
            pass
    parser = argparse.ArgumentParser(
        prog='vuln-scan',
        description='VulnGuard Security Scanner - Scan code and websites for vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Local file scanning
  %(prog)s                          # Scan current directory
  %(prog)s --path ./src             # Scan specific directory
  %(prog)s --fail-on medium         # Fail on medium+ severity
  %(prog)s --json results.json      # Export JSON report

  # Website scanning
  %(prog)s --url https://example.com     # Scan a website
  %(prog)s --url example.com --json     # Scan and export to JSON
  %(prog)s --url https://api.test.com   # Scan API endpoint

  # HTML/CSS/JS file scanning
  %(prog)s --path ./public            # Scan HTML/CSS/JS files
        """
    )

    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest='command', help='Scan mode')

    # === LOCAL SCAN MODE ===
    local_parser = subparsers.add_parser('local', help='Scan local files (default)')
    local_parser.add_argument(
        '--path', '-p',
        type=Path,
        default=Path('.'),
        help='Path to scan (default: current directory)'
    )
    local_parser.add_argument(
        '--fail-on',
        choices=['critical', 'high', 'medium', 'low', 'none'],
        default='high',
        help='Minimum severity to fail build (default: high)'
    )
    local_parser.add_argument(
        '--sarif',
        type=Path,
        help='Export SARIF report to file'
    )
    local_parser.add_argument(
        '--json',
        type=Path,
        help='Export JSON report to file'
    )
    local_parser.add_argument(
        '--patches',
        type=Path,
        help='Export patches to directory'
    )
    local_parser.add_argument(
        '--apply-fixes',
        action='store_true',
        help='Auto-apply high-confidence fixes (use with caution)'
    )
    local_parser.add_argument(
        '--config',
        type=Path,
        help='Path to configuration file (.json)'
    )
    local_parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress output (useful for CI)'
    )

    # === WEB SCAN MODE ===
    web_parser = subparsers.add_parser('web', help='Scan a website')
    web_parser.add_argument(
        'url',
        help='URL to scan (e.g., https://example.com)'
    )
    web_parser.add_argument(
        '--json',
        type=Path,
        help='Export JSON report to file'
    )
    web_parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )

    # === URL SHORTCUT ===
    parser.add_argument(
        '--url', '-u',
        help='Quick scan URL without subcommand'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    args = parser.parse_args()

    # Handle --url shortcut
    if args.url:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            exit_code = loop.run_until_complete(scan_website_async(args.url, args))
            sys.exit(exit_code)
        finally:
            loop.close()

    # Handle subcommands
    if args.command == 'local' or args.command is None:
        # Default to local scan
        if args.command is None:
            # Re-parse to get default path
            args.path = Path('.')
            args.fail_on = 'high'
            args.sarif = None
            args.json = None
            args.patches = None
            args.apply_fixes = False
            args.config = None
            args.quiet = False
        exit_code = scan_local_files(args)
        sys.exit(exit_code)

    elif args.command == 'web':
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            exit_code = loop.run_until_complete(scan_website_async(args.url, args))
            sys.exit(exit_code)
        finally:
            loop.close()


if __name__ == '__main__':
    main()
