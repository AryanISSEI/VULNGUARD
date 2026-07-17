---
name: decrypt-report
description: |
  Use this skill to decrypt and read a locked/encrypted vulnerability report file (.enc, .json.enc, or any encrypted report)
  using the backend's Fernet report encryption module.
metadata:
  version: v1
  publisher: Antigravity
---

# Decrypt Vulnerability Report Skill

When a user asks you to read, analyze, or process an encrypted/locked vulnerability report file, use this skill.

## Instructions

1. Run the backend decryption command via terminal to decrypt the report and output its plaintext to stdout.
   
   Command:
   ```bash
   .venv\Scripts\python.exe -m scanner.encryption.report_encryption decrypt <file_path>
   ```

2. Read the command's stdout. The output will contain the decrypted plaintext vulnerability report.

3. Process or analyze the report as requested by the user.

> [!WARNING]
> Do NOT rewrite the encrypted file back to disk unless requested. Simply read the stdout.
> Ensure that VULN_REPORT_ENCRYPTION_KEY is defined in your environment (it will load from .env automatically).
