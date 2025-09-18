from Crypto.Cipher import AES
import base64
import hashlib

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def encrypt(raw, key):
    raw = pad(raw)
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(raw.encode())).decode('utf-8')

def decrypt(enc, key):
    enc = base64.b64decode(enc)
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(enc).decode('utf-8'))
