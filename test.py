from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
import json
import base64

# Generate ECC key for signing
private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
public_key = private_key.public_key()

# Serialize public key for later verification
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def hash_password(password, salt):
    # Hashing the password with MD5 (not recommended for production)
    dk = PBKDF2HMAC(
        algorithm=hashes.MD5(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.b64encode(dk.derive(password.encode()))

def encrypt_data(data):
    key = urandom(32)  # AES key
    iv = urandom(16)   # Initialization vector for OFB mode
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return ct, key, iv

def sign_data(data, private_key):
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def store_data(users, filename="users.enc"):
    data = json.dumps(users).encode()
    encrypted_data, key, iv = encrypt_data(data)
    signature = sign_data(encrypted_data, private_key)
    
    with open(filename, 'wb') as f:
        f.write(encrypted_data)
        f.write(signature)
        f.write(key)
        f.write(iv)

def main():
    users = {}
    for i in range(3):  # Run the setup for 3 users
        username = input("Enter username: ")
        password = input("Set your password: ")
        salt = urandom(16)
        password_hash = hash_password(password, salt)
        users[username] = {'hash': password_hash.decode('utf-8'), 'salt': base64.b64encode(salt).decode('utf-8')}
    
    store_data(users)

if __name__ == "__main__":
    main()
