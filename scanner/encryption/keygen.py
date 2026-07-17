import sys
from cryptography.fernet import Fernet

def main():
    key = Fernet.generate_key().decode('utf-8')
    print("=" * 60)
    print("            VULNGUARD REPORT ENCRYPTION KEY GENERATOR")
    print("=" * 60)
    print("Add the following key to your .env file:")
    print()
    print(f"VULN_REPORT_ENCRYPTION_KEY={key}")
    print()
    print("=" * 60)
    print("Keep this key secure. If lost, encrypted reports cannot be recovered.")
    print("=" * 60)

if __name__ == "__main__":
    main()
