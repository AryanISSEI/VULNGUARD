import os
import pytest
from pathlib import Path
from cryptography.fernet import Fernet
from scanner.encryption.report_encryption import encrypt_report, decrypt_for_ai

def test_encryption_decryption(tmp_path, monkeypatch):
    # 1. Generate a test key
    test_key = Fernet.generate_key().decode('utf-8')
    
    # 2. Set the environment variable
    monkeypatch.setenv("VULN_REPORT_ENCRYPTION_KEY", test_key)
    
    # 3. Create a test report file
    report_file = tmp_path / "test_report.json"
    plaintext_content = '{"findings": [{"id": "TEST-1", "message": "Test vulnerability"}]}'
    report_file.write_text(plaintext_content, encoding='utf-8')
    
    # 4. Encrypt it
    encrypt_report(report_file)
    
    # Verify file is not plaintext anymore
    encrypted_content = report_file.read_bytes()
    assert encrypted_content != plaintext_content.encode('utf-8')
    
    # 5. Decrypt it
    decrypted_content = decrypt_for_ai(report_file)
    
    # Verify decrypted content matches original plaintext
    assert decrypted_content == plaintext_content

def test_missing_key_raises_error(tmp_path, monkeypatch):
    monkeypatch.delenv("VULN_REPORT_ENCRYPTION_KEY", raising=False)
    
    report_file = tmp_path / "test_report.json"
    report_file.write_text("plain text", encoding='utf-8')
    
    with pytest.raises(ValueError, match="VULN_REPORT_ENCRYPTION_KEY environment variable is not set"):
        encrypt_report(report_file)
        
    with pytest.raises(ValueError, match="VULN_REPORT_ENCRYPTION_KEY environment variable is not set"):
        decrypt_for_ai(report_file)
