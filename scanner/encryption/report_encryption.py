import os
import sys
from pathlib import Path
from cryptography.fernet import Fernet

def get_key() -> bytes:
    key_str = os.getenv("VULN_REPORT_ENCRYPTION_KEY")
    if not key_str:
        # Try manual fallback parse of .env
        dot_env = Path.cwd() / ".env"
        if not dot_env.exists():
            dot_env = Path(__file__).resolve().parents[2] / ".env"
        
        if dot_env.exists():
            for line in dot_env.read_text(encoding='utf-8', errors='ignore').splitlines():
                if '=' in line and not line.strip().startswith('#'):
                    k, v = line.split('=', 1)
                    if k.strip() == "VULN_REPORT_ENCRYPTION_KEY":
                        key_str = v.strip().strip('"\'')
                        os.environ[k.strip()] = key_str
                        break

    if not key_str:
        raise ValueError(
            "VULN_REPORT_ENCRYPTION_KEY environment variable is not set. "
            "Please generate a key and set it in your environment or .env file."
        )
    return key_str.strip().encode('utf-8')

def encrypt_report(file_path: str | Path) -> None:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
        
    key = get_key()
    fernet = Fernet(key)
    
    plaintext = path.read_text(encoding='utf-8')
    ciphertext = fernet.encrypt(plaintext.encode('utf-8'))
    
    # Write as binary
    path.write_bytes(ciphertext)

def decrypt_for_ai(file_path: str | Path) -> str:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
        
    key = get_key()
    fernet = Fernet(key)
    
    ciphertext = path.read_bytes()
    plaintext_bytes = fernet.decrypt(ciphertext)
    return plaintext_bytes.decode('utf-8')

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m scanner.encryption.report_encryption <encrypt|decrypt> <file_path>", file=sys.stderr)
        sys.exit(1)
        
    action = sys.argv[1].lower()
    file_path = sys.argv[2]
    
    # Load .env if dotenv/os.environ doesn't have it (fallback)
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        # Simple manual fallback parse of .env if it exists in current dir
        dot_env = Path(".env")
        if dot_env.exists():
            for line in dot_env.read_text(encoding='utf-8', errors='ignore').splitlines():
                if '=' in line and not line.strip().startswith('#'):
                    k, v = line.split('=', 1)
                    os.environ[k.strip()] = v.strip().strip('"\'')
                    
    try:
        if action == "encrypt":
            encrypt_report(file_path)
            print(f"Successfully encrypted {file_path}")
        elif action == "decrypt":
            plaintext = decrypt_for_ai(file_path)
            # Print plaintext directly to stdout
            print(plaintext)
        else:
            print(f"Unknown action: {action}", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
