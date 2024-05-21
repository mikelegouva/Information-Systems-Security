#This code was designed by Michail Gouvalaris on May 21th 2024.
#It is intended for academic use at the Dept. of Informatics and Telecommunication of University of Ioannina.

#This code was designed and compiled at Python 3.12.

#This Python script securely manages user passwords by hashing and salting them, encrypting the data with AES, and signing it with an elliptic curve digital signature. Upon login, it verifies the signature and decrypts the data to authenticate users.

#Last Update May 21th 2024

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
import json
import base64

# Generate ECC key for signing (for demonstration, we generate it again)
private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
public_key = private_key.public_key()

def hash_password(password, salt):
    dk = PBKDF2HMAC(
        algorithm=hashes.MD5(),  # Not recommended for production
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.b64encode(dk.derive(password.encode()))

def encrypt_data(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return ct

def decrypt_data(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def sign_data(data, private_key):
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

def verify_signature(data, signature, public_key):
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        return False

def store_data(users, filename="users.enc"):
    data = json.dumps(users).encode()
    key = urandom(32)
    iv = urandom(16)
    encrypted_data = encrypt_data(data, key, iv)
    signature = sign_data(encrypted_data, private_key)
    
    # Store the lengths of each part for correct retrieval
    with open(filename, 'wb') as f:
        f.write(len(encrypted_data).to_bytes(4, 'big'))
        f.write(len(signature).to_bytes(4, 'big'))
        f.write(encrypted_data)
        f.write(signature)
        f.write(key)
        f.write(iv)

def load_data(filename="users.enc"):
    with open(filename, 'rb') as f:
        encrypted_data_len = int.from_bytes(f.read(4), 'big')
        signature_len = int.from_bytes(f.read(4), 'big')
        encrypted_data = f.read(encrypted_data_len)
        signature = f.read(signature_len)
        key = f.read(32)
        iv = f.read(16)
        
    return encrypted_data, signature, key, iv

def main():
    # Setup or load data
    users = {}
    for i in range(3):
        username = input("Enter username: ")
        password = input("Set your password: ")
        salt = urandom(16)
        password_hash = hash_password(password, salt)
        users[username] = {'hash': password_hash.decode('utf-8'), 'salt': base64.b64encode(salt).decode('utf-8')}
    
    store_data(users)
    
    # Verification process
    encrypted_data, signature, key, iv = load_data()
    if verify_signature(encrypted_data, signature, public_key):
        print("Signature verified!")
        data = decrypt_data(encrypted_data, key, iv)
        print("Decrypted data:", data.decode())
    else:
        print("Signature verification failed!")

if __name__ == "__main__":
    main()
