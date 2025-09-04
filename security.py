from cryptography.fernet import Fernet
from flask import current_app

def _fernet():
    key = current_app.config['FERNET_KEY']
    if not key:
        raise RuntimeError('FERNET_KEY not configured')
    return Fernet(key.encode() if isinstance(key, str) else key)

def encrypt_text(plain: str) -> bytes:
    return _fernet().encrypt(plain.encode())

def decrypt_text(token: bytes) -> str:
    return _fernet().decrypt(token).decode()
