import os
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from cryptography.fernet import Fernet

from scanner.api import app

client = TestClient(app)

def test_api_decrypt_success(tmp_path, monkeypatch):
    # Setup test key and env
    test_key = Fernet.generate_key().decode('utf-8')
    monkeypatch.setenv("VULN_REPORT_ENCRYPTION_KEY", test_key)
    
    # Write a test report file
    report_content = '{"status": "safe", "findings": []}'
    
    # Monkeypatch Path.cwd() to return our tmp_path
    monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
    
    # Encrypt the report using Fernet
    fernet = Fernet(test_key.encode('utf-8'))
    ciphertext = fernet.encrypt(report_content.encode('utf-8'))
    
    report_file = tmp_path / "test_report.enc"
    report_file.write_bytes(ciphertext)
    
    # Call endpoint
    response = client.get("/api/reports/decrypt/test_report.enc")
    assert response.status_code == 200
    assert response.json() == {"status": "safe", "findings": []}

def test_api_decrypt_path_traversal(monkeypatch):
    # Attempt directory traversal
    response = client.get("/api/reports/decrypt/..%2F..%2Fsome_file.enc")
    assert response.status_code in (400, 404)
    if response.status_code == 400:
        assert "Directory traversal is not allowed" in response.json()["detail"]

def test_api_decrypt_not_found(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
    
    response = client.get("/api/reports/decrypt/nonexistent.enc")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]
