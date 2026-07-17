# Quick Start Guide

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/fix-first-scanner.git
cd fix-first-scanner

# Install the scanner
pip install -e .

# Install dashboard dependencies
cd dashboard
npm install
```

## Running the Scanner

### Local Scan

```bash
# Scan current directory
vuln-scan

# Scan specific directory
vuln-scan --path ./src

# Generate SARIF for GitHub
vuln-scan --sarif results.sarif --json results.json

# Fail on medium or higher
vuln-scan --fail-on medium
```

### Test with Sample Files

```bash
# Scan the vulnerable test fixtures
vuln-scan --path tests/fixtures --json sample-results.json

# View the output
vuln-scan --path tests/fixtures/vulnerable_api.py
```

## Using the Dashboard

```bash
cd dashboard
npm run dev
```

Then:
1. Open http://localhost:5173
2. Upload `tests/fixtures/sample-output.json`
3. Browse findings and view suggested fixes

## GitHub Actions Setup

1. Copy the action to your repository:
```bash
mkdir -p .github/actions
cp -r /path/to/fix-first-scanner/action .github/actions/vuln-scan
```

2. Create workflow (`.github/workflows/security.yml`):
```yaml
name: Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/vuln-scan
        with:
          fail-on: high
          pr-comments: true
```

## Understanding Output

### CLI Output Example
```
============================================================
  FIX-FIRST SECURITY SCAN RESULTS
============================================================

  Files scanned: 2
  Duration: 145ms

  VULNERABILITIES BY SEVERITY:
    Critical: 1
    High:     4
    Medium:   1
    Low:      0

  Patches available: 6

  TOP FINDINGS:
  1. [CRITICAL] XSS - eval()
     tests/fixtures/vulnerable_components.jsx:13
     Fix available: Remove eval() - use JSON.parse()

  2. [HIGH] SQL Injection
     tests/fixtures/vulnerable_api.py:18
     Fix available: Use parameterized query

  RESULT: FAILED - Critical/High severity issues found
```

### JSON Output Structure
```json
{
  "findings": [
    {
      "id": "SQLI-vulnerable_api-18",
      "rule": "SQL Injection",
      "severity": "high",
      "message": "SQL injection via f-string interpolation",
      "file": "tests/fixtures/vulnerable_api.py",
      "line": 18,
      "snippet": "cursor.execute(f\"SELECT * FROM users...\")",
      "patch": {
        "description": "Use parameterized query",
        "fixed_code": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
        "explanation": "Parameterized queries prevent SQL injection...",
        "confidence": "high"
      }
    }
  ],
  "summary": {
    "total": 6,
    "critical": 1,
    "high": 4,
    "patches_available": 6
  }
}
```

## Fixing Vulnerabilities

### Option 1: Manual Fix
Use the suggested code in the scanner output or dashboard.

### Option 2: Apply Patches (CLI)
```bash
# Auto-apply high-confidence fixes
vuln-scan --apply-fixes

# Export patches without applying
vuln-scan --patches ./patches/
```

### Option 3: GitHub PR Comments
Enable `pr-comments: true` in the GitHub Action to get inline fix suggestions.

## Configuration

Create `.vuln-scan.json` in your project root:
```json
{
  "fail_on": "high",
  "rules": ["sqli", "xss", "auth"],
  "exclude": ["tests/", "migrations/"],
  "include": ["src/"]
}
```

## Troubleshooting

### "No findings" when vulnerabilities exist
- Check file extensions are `.py`, `.js`, `.jsx`, `.ts`, `.tsx`
- Ensure files aren't in excluded directories
- Verify Python version >= 3.9

### Tree-sitter import errors
```bash
pip install tree-sitter tree-sitter-python tree-sitter-javascript
```

### Dashboard won't load
```bash
cd dashboard
npm install
npm run dev
```

## Next Steps

1. **Integrate into CI/CD**: Add the GitHub Action to your PR workflow
2. **Configure thresholds**: Set `fail-on` based on your risk tolerance
3. **Train your team**: Share the dashboard link for security reviews
4. **Customize rules**: Add organization-specific patterns
