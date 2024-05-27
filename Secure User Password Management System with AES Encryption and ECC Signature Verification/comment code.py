from cryptography.hazmat.primitives import hashes, serialization  # Importing necessary modules for cryptographic operations
from cryptography.hazmat.primitives.asymmetric import ec  # Importing elliptic curve cryptography module
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Importing PBKDF2HMAC for key derivation
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Importing classes for symmetric encryption
from cryptography.hazmat.backends import default_backend  # Importing default backend for cryptographic operations
from os import urandom  # Importing urandom for generating random bytes
import json  # Importing JSON module for serialization and deserialization
import base64  # Importing base64 for encoding and decoding binary data

# Generate ECC key for signing (for demonstration, we generate it again)
private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())  # Generating a private key using elliptic curve cryptography with SECP384R1 curve
public_key = private_key.public_key()  # Deriving public key from the generated private key

def hash_password(password, salt):  # Defining a function to hash passwords
    dk = PBKDF2HMAC(
        algorithm=hashes.MD5(),  # Using MD5 hashing algorithm (not recommended for production)
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )  # Initializing PBKDF2HMAC object with specified parameters
    return base64.b64encode(dk.derive(password.encode()))  # Encoding the derived key in Base64 and returning it

def encrypt_data(data, key, iv):  # Defining a function to encrypt data
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())  # Initializing a cipher object for AES encryption in OFB mode
    encryptor = cipher.encryptor()  # Creating an encryptor object
    ct = encryptor.update(data) + encryptor.finalize()  # Encrypting the data
    return ct  # Returning the encrypted data

def decrypt_data(data, key, iv):  # Defining a function to decrypt data
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())  # Initializing a cipher object for AES decryption in OFB mode
    decryptor = cipher.decryptor()  # Creating a decryptor object
    return decryptor.update(data) + decryptor.finalize()  # Decrypting the data

def sign_data(data, private_key):  # Defining a function to sign data
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))  # Signing the data using the private key

def verify_signature(data, signature, public_key):  # Defining a function to verify signature
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))  # Verifying the signature against the data using the public key
        return True  # Returning True if signature verification is successful
    except Exception as e:
        return False  # Returning False if signature verification fails

def store_data(users, filename="users.enc"):  # Defining a function to store encrypted data
    data = json.dumps(users).encode()  # Serializing the users' data to JSON format and encoding it to bytes
    key = urandom(32)  # Generating a random key for encryption
    iv = urandom(16)  # Generating a random IV for encryption
    encrypted_data = encrypt_data(data, key, iv)  # Encrypting the data
    signature = sign_data(encrypted_data, private_key)  # Signing the encrypted data
    with open(filename, 'wb') as f:  # Opening the file in binary write mode
        f.write(len(encrypted_data).to_bytes(4, 'big'))  # Writing the length of encrypted data to the file
        f.write(len(signature).to_bytes(4, 'big'))  # Writing the length of signature to the file
        f.write(encrypted_data)  # Writing the encrypted data to the file
        f.write(signature)  # Writing the signature to the file
        f.write(key)  # Writing the key to the file
        f.write(iv)  # Writing the IV to the file

def load_data(filename="users.enc"):  # Defining a function to load encrypted data
    with open(filename, 'rb') as f:  # Opening the file in binary read mode
        encrypted_data_len = int.from_bytes(f.read(4), 'big')  # Reading the length of encrypted data from the file
        signature_len = int.from_bytes(f.read(4), 'big')  # Reading the length of signature from the file
        encrypted_data = f.read(encrypted_data_len)  # Reading the encrypted data from the file
        signature = f.read(signature_len)  # Reading the signature from the file
        key = f.read(32)  # Reading the key from the file
        iv = f.read(16)  # Reading the IV from the file
    return encrypted_data, signature, key, iv  # Returning the encrypted data, signature, key, and IV

def main():  # Defining the main function
    users = {}  # Initializing an empty dictionary to store user data
    for i in range(3):  # Looping to input data for three users
        username = input("Enter username: ")  # Prompting user to enter username
        password = input("Set your password: ")  # Prompting user to set password
        salt = urandom(16)  # Generating a random salt for password hashing
        password_hash = hash_password(password, salt)  # Hashing the password
        users[username] = {'hash': password_hash.decode('utf-8'), 'salt': base64.b64encode(salt).decode('utf-8')}  # Storing hashed password and salt
    store_data(users)  # Storing the encrypted data
    encrypted_data, signature, key, iv = load_data()  # Loading encrypted data
    if verify_signature(encrypted_data, signature, public_key):  # Verifying the signature
        print("Signature verified!")  # Printing message if signature verification is successful
        data = decrypt_data(encrypted_data, key, iv)  # Decrypting the data
        print("Decrypted data:", data.decode())  # Printing the decrypted data
    else:
        print("Signature verification failed!")  # Printing message if signature verification fails

if __name__ == "__main__":  # Checking if the script is run directly
    main()  # Calling the main function
