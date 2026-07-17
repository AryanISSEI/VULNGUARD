# Fix-First Scanner Architecture

## Overview

A developer-first security scanner that detects OWASP vulnerabilities (SQLi, XSS, auth issues) and generates directly usable code fixes instead of generic reports.

## Core Principles

1. **Fix-First**: Generate patches, not just reports
2. **High Confidence**: Only auto-suggest fixes we're confident in
3. **CI/CD Native**: Designed for pull request workflows
4. **Zero False Positives**: Better to miss than to noise

## System Components

### 1. Scanner Engine (`scanner/`)

```
scanner/
├── core.py              # Orchestration and CLI
├── findings.py          # Data models (Finding, Patch, ScanResult)
├── cli.py              # Command-line interface
├── parsers/            # Language-specific AST parsers
│   ├── python.py       # FastAPI/Python analysis
│   └── javascript.py   # React/JS/TS analysis
└── rules/              # Security detection rules
    ├── sqli.py         # SQL injection detection + patches
    ├── xss.py          # XSS detection + patches
    └── auth.py         # Auth misconfig detection + patches
```

**Key Design Decisions:**
- Uses `tree-sitter` for robust AST parsing (tolerates syntax errors)
- Rules return `Finding` objects with optional `Patch`
- Confidence scoring (high/medium/low) for each patch
- SARIF output for GitHub integration

### 2. GitHub Action (`action/`)

```yaml
Composite action that:
1. Installs Python scanner
2. Runs scan on PR
3. Uploads SARIF to GitHub Security tab
4. Posts inline PR comments with fixes
5. Optionally applies high-confidence fixes
```

**Workflow Integration:**
```yaml
- uses: your-org/fix-first-scanner/action@v1
  with:
    fail-on: high        # Fail build on high/critical
    pr-comments: true    # Post review comments
    apply-fixes: false   # Auto-apply patches (dangerous)
```

### 3. Dashboard (`dashboard/`)

React + Vite + Tailwind SPA that:
- Loads scan results JSON
- Displays severity summary cards
- Shows findings with expandable fix previews
- Filters by severity/rule/patch availability

**No Backend Required** - Reads from uploaded JSON or URL param.

## Detection Rules

### SQL Injection (`rules/sqli.py`)

**Patterns Detected:**
- f-string interpolation: `f"SELECT * FROM users WHERE id = {user_id}"`
- .format() method: `"SELECT * FROM users WHERE id = {}".format(user_id)`
- % formatting: `"SELECT * FROM users WHERE id = %s" % user_id`

**Patch Generation:**
```python
# Before:
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# After (high confidence):
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### XSS (`rules/xss.py`)

**Patterns Detected:**
- React: `dangerouslySetInnerHTML={{ __html: content }}`
- DOM: `element.innerHTML = userInput`
- JS: `eval(userInput)`
- Storage: `localStorage.setItem('token', jwt)`

**Patch Generation:**
```jsx
// Before:
<div dangerouslySetInnerHTML={{ __html: content }} />

// After:
// const clean = DOMPurify.sanitize(content);
<div>{clean}</div>
```

### Auth Issues (`rules/auth.py`)

**Patterns Detected:**
- Hardcoded secrets: `SECRET_KEY = "abc123"`
- JWT algorithm "none": `algorithms=["none"]`
- Missing cookie flags: no `httponly`/`secure`/`samesite`
- Wildcard CORS: `allow_origins=["*"]`

**Patch Generation:**
```python
# Before:
SECRET_KEY = "supersecret123"

# After:
SECRET_KEY = os.environ['SECRET_KEY']
```

## Data Flow

```
Source Code
     ↓
[Parser] → AST
     ↓
[Rules] → Findings[] with Patches
     ↓
[Core] → ScanResult
     ↓
┌─────────────┬──────────────┬─────────────┐
│  SARIF      │   JSON       │   PR        │
│  (GitHub)   │  (Dashboard) │  Comments   │
└─────────────┴──────────────┴─────────────┘
```

## Confidence Scoring

| Pattern | Confidence | Rationale |
|---------|-----------|-----------|
| Single f-string SQLi | HIGH | Clear replacement pattern |
| Multiple interpolations | MEDIUM | Complex query structure |
| Variable-only execute | LOW | Need context to generate query |
| React dangerouslySetInnerHTML | HIGH | Standard DOMPurify fix |
| Eval removal | HIGH | Always wrong, easy fix |
| innerHTML → textContent | MEDIUM | Might need HTML sometimes |

## Patch Format

Patches use unified diff format:
```diff
--- a/api/routes/users.py
+++ b/api/routes/users.py
@@ -15,7 +15,7 @@
 def get_user(user_id: str):
     conn = sqlite3.connect(DB)
     cursor = conn.cursor()
-    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
+    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
     return cursor.fetchone()
```

This format is:
- GitHub-compatible (for PR suggestions)
- `git apply` compatible
- Human-readable

## CI/CD Integration

### GitHub Actions

**On Pull Request:**
1. Scan changed files only
2. Post findings as PR review comments
3. Fail build if `critical/high` found
4. Show "Apply Fix" buttons for high-confidence patches

**On Push to Main:**
1. Full repository scan
2. Upload SARIF to Security tab
3. Create dashboard artifact

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean or below threshold |
| 1 | Vulnerabilities found at/above threshold |

## Extensibility

### Adding a New Rule

1. Create `scanner/rules/new_rule.py`:
```python
class NewRule:
    RULE_ID = "LANG-XXX-001"
    RULE_NAME = "Vulnerability Name"

    def analyze(self, file_path: Path, source: Optional[str]) -> List[Finding]:
        findings = []
        # ... detection logic ...
        findings.append(Finding(
            id="...",
            rule_id=self.RULE_ID,
            # ...
            patch=Patch(...)
        ))
        return findings
```

2. Register in `scanner/rules/__init__.py`

3. Add test in `tests/test_scanner.py`

### Adding a Language Parser

1. Create `scanner/parsers/new_lang.py` with `NewLangParser` class
2. Register in `scanner/parsers/__init__.py`
3. Add to `SCAN_EXTENSIONS` in `scanner/core.py`

## Performance Considerations

- **Parallel Scanning**: Process files in parallel (ThreadPoolExecutor)
- **Incremental Scans**: Only scan changed files in PRs
- **Lazy Loading**: Tree-sitter grammars loaded on demand
- **Timeout**: 30s per file, skip if exceeded

## Security Considerations

- Never execute detected code
- AST parsing only, no eval/exec
- Treat source code as untrusted input
- Sanitize any output displayed to users

## Future Enhancements

1. **Additional Rules**:
   - Path traversal
   - SSRF
   - Insecure deserialization
   - CSRF

2. **Language Support**:
   - Go (Gin/Echo)
   - Ruby (Rails)
   - Java (Spring)

3. **Auto-Fix PRs**:
   - Create PRs with applied fixes
   - Link to security documentation

4. **ML-Based Detection**:
   - Train on vulnerability datasets
   - Reduce false positives further
