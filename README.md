# Fix-First Vulnerability Scanner

A developer-first security scanner that integrates into CI/CD and generates fix-ready patches instead of generic reports.

## Quick Start

```bash
# Install
pip install fix-first-scanner

# Scan current directory
vuln-scan

# Scan with specific options
vuln-scan --path ./src --fail-on medium --sarif results.sarif
```

## GitHub Action

```yaml
name: Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/fix-first-scanner/action@v1
        with:
          fail-on: high
          pr-comments: true
```

## Features

- **SQL Injection Detection**: Finds unsafe query construction in Python/FastAPI
- **XSS Prevention**: Detects dangerous React patterns and DOM manipulation
- **Auth Misconfiguration**: Identifies JWT issues, weak secrets, insecure cookies
- **Auto-Fix Generation**: Produces ready-to-apply patches with explanations
- **SARIF Export**: Native GitHub integration for PR comments
- **React Dashboard**: Visualize findings with one-click fix application

## Configuration

Create `.vuln-scan.json`:

```json
{
  "fail_on": "high",
  "rules": ["sqli", "xss", "auth"],
  "exclude": ["tests/", "migrations/"],
  "include": ["src/"]
}
```

## Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Upload a scan results JSON file to visualize findings and explore suggested fixes.

## License

MIT
