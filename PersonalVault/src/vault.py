from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os, json, zstandard as zstd, secrets

KEY_FILE = 'vault_private.pem'

def generate_keypair(passphrase: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()))
    with open(KEY_FILE, 'wb') as f:
        f.write(pem)
    return private_key, private_key.public_key()

def load_private_key(passphrase: str):
    with open(KEY_FILE, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase.encode())

def encrypt_file(path, public_key):
    aes_key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(aes_key)
    with open(path, 'rb') as f:
        data = zstd.compress(f.read())
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, data, None)
    with open(path + '.enc', 'wb') as f:
        f.write(nonce + ct)
    enc_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    with open(path + '.key.enc', 'wb') as f:
        f.write(enc_key)
    os.remove(path)

def decrypt_file(enc_path, private_key):
    with open(enc_path.replace('.enc', '.key.enc'), 'rb') as f:
        aes_key = private_key.decrypt(f.read(), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    aes = AESGCM(aes_key)
    with open(enc_path, 'rb') as f:
        blob = f.read()
    pt = aes.decrypt(blob[:12], blob[12:], None)
    with open(enc_path.replace('.enc', ''), 'wb') as f:
        f.write(zstd.decompress(pt))
