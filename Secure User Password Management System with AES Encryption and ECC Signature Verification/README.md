# Secure Password Management System

## Introduction
This script was designed by Michail Gouvalaris on May 21st, 2024, specifically for academic purposes at the Department of Informatics and Telecommunications at the University of Ioannina. It showcases secure handling of user passwords through encryption, hashing, and digital signatures.

## Features
- **Password Hashing**: Uses PBKDF2 HMAC with MD5 for hashing and salting passwords.
- **AES Encryption**: Encrypts user data using AES in OFB mode to ensure confidentiality.
- **Elliptic Curve Digital Signatures**: Implements ECC for signing encrypted data, ensuring integrity and non-repudiation.
- **Signature Verification**: Upon user login, the system verifies the digital signature to authenticate data.
- **Data Decryption**: Decrypts the encrypted data after verifying the digital signature.

## Prerequisites
- Python 3.12
- `cryptography` library

## Installation
Install the required Python library using pip:
```bash
pip install cryptography
