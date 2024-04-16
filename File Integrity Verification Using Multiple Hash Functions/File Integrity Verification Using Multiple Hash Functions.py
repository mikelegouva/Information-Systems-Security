#This code was designed by Michail Gouvalaris on April 17th 2024.
#It is intended for academic use at the Dept. of Informatics and Telecommunication of University of Ioannina.

#This code was designed and compiled at Python 3.12 .

#The provided Python script is designed to ensure the integrity of a file by calculating and comparing its cryptographic hashes using multiple algorithms (MD5, SHA-1, SHA-256, and SHA3-256). The script reads a specified file in binary mode in manageable chunks, updates hash objects for each algorithm with these chunks, and then stores the results as hexadecimal strings. It includes a function to recalculate these hashes at a later time to verify that the file has not been altered, by comparing the new hashes against the originally stored values, effectively serving as a tool for detecting any modifications to the file.

#Last Update April 17th 2024

import hashlib

def calculate_hashes(file_path):
    """Calculate MD5, SHA-1, SHA-256, and SHA3-256 hashes for the specified file."""
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    hash_sha3_256 = hashlib.sha3_256()

    with open(file_path, "rb") as file:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: file.read(4096), b""):
            hash_md5.update(byte_block)
            hash_sha1.update(byte_block)
            hash_sha256.update(byte_block)
            hash_sha3_256.update(byte_block)

    return {
        "MD5": hash_md5.hexdigest(),
        "SHA-1": hash_sha1.hexdigest(),
        "SHA-256": hash_sha256.hexdigest(),
        "SHA3-256": hash_sha3_256.hexdigest()
    }

def check_integrity(original_hashes, current_hashes):
    """Compare the original and current hashes to check file integrity."""
    results = {}
    for key in original_hashes.keys():
        if original_hashes[key] == current_hashes[key]:
            results[key] = True
        else:
            results[key] = False
    return results

# Example usage:
file_path = r"PATH"
original_hashes = calculate_hashes(file_path)
print("Original Hashes:", original_hashes)

# Simulate later integrity check (file should be unchanged for a valid check)
current_hashes = calculate_hashes(file_path)
integrity_check = check_integrity(original_hashes, current_hashes)
print("Integrity Check Results:", integrity_check)
