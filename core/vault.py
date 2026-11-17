import base64
import hashlib
import os
import subprocess
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from .logger import logger

VAULT_DIR = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "UnSecurityUnlock" / "quarantine"
VAULT_DIR.mkdir(parents=True, exist_ok=True)

MASTER_FILE = VAULT_DIR / ".master"
SALT_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITER = 200_000
NONCE_SIZE = 12


# ---------- мастер-пароль ----------

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITER,
    )
    return kdf.derive(password.encode("utf-8"))


def is_initialized() -> bool:
    return MASTER_FILE.exists()


def init_master(password: str) -> bool:
    """Создать мастер-пароль. Только один раз."""
    if is_initialized():
        return False
    salt = os.urandom(SALT_SIZE)
    key = _derive_key(password, salt)
    verifier = hashlib.sha256(key + b"verify").hexdigest()
    data = {
        "salt": base64.b64encode(salt).decode(),
        "verifier": verifier,
    }
    import json
    MASTER_FILE.write_text(json.dumps(data), encoding="utf-8")
    _harden_acl()
    logger.info("vault: master initialized")
    return True


def verify_master(password: str) -> bool:
    """Проверить мастер-пароль."""
    if not is_initialized():
        return False
    import json
    try:
        data = json.loads(MASTER_FILE.read_text(encoding="utf-8"))
        salt = base64.b64decode(data["salt"])
        verifier = data["verifier"]
        key = _derive_key(password, salt)
        return hashlib.sha256(key + b"verify").hexdigest() == verifier
    except Exception as e:
        logger.error("vault verify failed: %s", e)
        return False


def get_key(password: str) -> Optional[bytes]:
    """Получить ключ шифрования из пароля."""
    if not verify_master(password):
        return None
    import json
    data = json.loads(MASTER_FILE.read_text(encoding="utf-8"))
    salt = base64.b64decode(data["salt"])
    return _derive_key(password, salt)


# ---------- шифрование ----------

def encrypt_blob(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    aead = ChaCha20Poly1305(key)
    ct = aead.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_blob(key: bytes, blob: bytes) -> bytes:
    nonce = blob[:NONCE_SIZE]
    ct = blob[NONCE_SIZE:]
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ct, None)


# ---------- ACL ----------

def _harden_acl() -> None:
    """Ограничить доступ к папке карантина: только Administrators + SYSTEM."""
    try:
        subprocess.run(
            ["icacls", str(VAULT_DIR), "/inheritance:r"],
            capture_output=True, timeout=15
        )
        subprocess.run(
            ["icacls", str(VAULT_DIR),
             "/grant:r", "Administrators:(OI)(CI)F",
             "/grant:r", "SYSTEM:(OI)(CI)F"],
            capture_output=True, timeout=15
        )
        logger.info("vault: ACL hardened")
    except Exception as e:
        logger.error("vault ACL failed: %s", e)
