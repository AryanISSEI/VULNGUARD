import hashlib
import random

def create_user():
    # Vulnerability: Weak hashing algorithm
    m = hashlib.md5()
    m.update(b"password123")
    hashed = m.digest()
    
    # Vulnerability: Hardcoded key
    encryption_key = "SuperSecretKeyForAES!!!"
    
    # Vulnerability: Insecure random
    salt = random.randint(1000, 9999)
    
    return {"hash": hashed, "salt": salt}