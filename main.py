import os
import json
import hashlib
import getpass
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


BASE_DIR = Path.home() / ".stuff/sys-integrity-2"
MAPPING_FILE = BASE_DIR / "mapping.json"


# Utility Functions

def ensure_dir():
    BASE_DIR.mkdir(parents=True, exist_ok=True)


def load_mapping():
    if MAPPING_FILE.exists():
        with open(MAPPING_FILE, "r") as f:
            return json.load(f)
    return {}


def save_mapping(mapping):
    with open(MAPPING_FILE, "w") as f:
        json.dump(mapping, f, indent=4)


def compute_sha256(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Encryption / Decryption

def encrypt_data(data: bytes, password: str):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return salt + iv + ciphertext


def decrypt_data(data: bytes, password: str):
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


# Core Logic

def save_state(file_path, password):
    file_path = str(file_path)
    mapping = load_mapping()

    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return

    ensure_dir()

    checksum = compute_sha256(file_path)

    with open(file_path, "rb") as f:
        content = f.read()

    combined = checksum.encode() + b"\n" + content
    encrypted = encrypt_data(combined, password)

    filename = secrets.token_hex(12) + ".enc"
    enc_path = BASE_DIR / filename

    with open(enc_path, "wb") as f:
        f.write(encrypted)

    mapping[file_path] = filename
    save_mapping(mapping)

    print(f"💾 Saved: {file_path}")


def check_state(file_path, password):
    file_path = str(file_path)
    mapping = load_mapping()

    if file_path not in mapping:
        print(f"⚠️ No saved state for {file_path}")
        return

    enc_path = BASE_DIR / mapping[file_path]

    with open(enc_path, "rb") as f:
        encrypted = f.read()

    try:
        decrypted = decrypt_data(encrypted, password)
    except Exception:
        print("❌ Wrong password or corrupted file")
        return

    saved_checksum, saved_content = decrypted.split(b"\n", 1)
    current_checksum = compute_sha256(file_path).encode()

    if saved_checksum == current_checksum:
        print(f"✅ No changes: {file_path}")
    else:
        print(f"⚠️ Modified: {file_path}")


def main():
    import sys

    if len(sys.argv) != 2 or sys.argv[1] not in ["save", "check"]:
        print("Usage: python script.py [save|check]")
        return

    mode = sys.argv[1]
    password = getpass.getpass("Enter password: ")

    files = input("Enter file paths (comma-separated): ").split(",")

    for f in files:
        f = f.strip()
        if mode == "save":
            save_state(f, password)
        else:
            check_state(f, password)


if __name__ == "__main__":
    main()