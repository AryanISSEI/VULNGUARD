import os
import tempfile
from pathlib import Path
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from dotenv import load_dotenv

load_dotenv()

from scanner.core import Scanner
from scanner.vuln_intel import enrich_finding

app = FastAPI(title="VulnGuard API")

# Allow CORS so the React dashboard can make requests to it
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this in production
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the scanner globally
scanner = Scanner()

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    """
    Accepts a raw source code file, writes it to a temporary directory,
    scans it using the core Scanner, and returns the JSON results.
    """
    # Create a temporary directory to dump the file
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        
        # Preserve original filename and extension
        filename = file.filename or "file"
        file_path = temp_dir_path / filename
        
        # Write the uploaded file content to disk
        content = await file.read()
        file_path.write_bytes(content)
        
        # Run the scanner on the specific file
        # We manually collect and scan to avoid directory recursion if not needed,
        # but calling `scanner.scan` with the directory works too.
        result = scanner.scan(file_path)
        
        # We can construct the JSON response similarly to how cli.py exports it,
        # but actually result.to_sarif() is directly usable since the dashboard supports SARIF!
        # Or we can return the custom JSON. Let's return the custom JSON format that the dashboard expects primarily.
        
        json_data = {
            'findings': [
                enrich_finding({
                    'id': f.id.replace(str(temp_dir_path), 'uploaded'),
                    'rule': f.rule_name,
                    'severity': f.severity.value,
                    'confidence': f.confidence.value,
                    'message': f.message,
                    'file': filename,  # obscure the temp path
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
            }
        }
        
    return json_data

from pydantic import BaseModel
from scanner.web_scanner import WebSecurityScanner

class UrlRequest(BaseModel):
    url: str

@app.post("/scan-url")
async def scan_url_endpoint(request: UrlRequest):
    """
    Scans a live website URL and returns the JSON results.
    """
    web_scanner = WebSecurityScanner()
    # WebSecurityScanner.scan_url is async
    result = await web_scanner.scan_url(request.url)
    
    # Map WebFinding schema to the Dashboard's expected format
    json_data = {
        'findings': [
            enrich_finding({
                'id': f.get('id', f'web-{i}'),
                'rule': f.get('rule_name', 'Web Vulnerability'),
                'severity': 'low' if f.get('severity') == 'info' else f.get('severity', 'medium'),
                'confidence': f.get('confidence', 'medium'),
                'message': f.get('message', ''),
                'file': f.get('url', request.url),  # Map url to file field
                'line': 1,
                'snippet': f.get('evidence', ''),
                'patch': {
                    'description': f.get('remediation', 'Fix the issue on the server'),
                    'fixed_code': f.get('remediation', ''),
                    'explanation': f.get('remediation', ''),
                    'confidence': 'high'
                } if f.get('remediation') else None
            }, f.get('rule_id', 'WEB-GENERIC'))
            for i, f in enumerate(result.get('findings', []))
        ],
        'summary': {
            'total': result.get('summary', {}).get('total', 0),
            'total_findings': result.get('summary', {}).get('total', 0),
            'critical': result.get('summary', {}).get('critical', 0),
            'high': result.get('summary', {}).get('high', 0),
            'medium': result.get('summary', {}).get('medium', 0),
            'low': result.get('summary', {}).get('low', 0) + result.get('summary', {}).get('info', 0),
            'patches_available': result.get('summary', {}).get('total', 0),
            'duration_ms': 0, # Not explicitly tracked in web scanner return dict yet
            'files_scanned': 1
        }
    }
    
    return json_data

class RepoRequest(BaseModel):
    url: str

@app.post("/scan-repo")
async def scan_repo_endpoint(request: RepoRequest):
    """
    Clones and scans a public Git repository.
    """
    import asyncio
    from scanner.repo_scanner import clone_and_scan
    from fastapi import HTTPException
    
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, clone_and_scan, request.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/reports/decrypt/{filename}")
async def decrypt_report_endpoint(filename: str):
    """
    Reads an encrypted vulnerability report file, decrypts it using the master key,
    and returns the plaintext report.
    """
    from fastapi import HTTPException
    from scanner.encryption.report_encryption import decrypt_for_ai
    
    # Path traversal check
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(
            status_code=400,
            detail="Invalid filename. Directory traversal is not allowed."
        )
        
    file_path = Path.cwd() / filename
    
    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Report file '{filename}' not found."
        )
        
    try:
        plaintext = decrypt_for_ai(file_path)
        try:
            import json
            return json.loads(plaintext)
        except json.JSONDecodeError:
            return {"raw_text": plaintext}
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Decryption failed: {str(e)}"
        )



if __name__ == "__main__":
    uvicorn.run("scanner.api:app", host="0.0.0.0", port=8000, reload=True)
