# File Integrity Checker

This Python script is designed to ensure the integrity of files by calculating and comparing their cryptographic hashes using multiple algorithms. It supports MD5, SHA-1, SHA-256, and SHA3-256 hash functions.

## Developed by
Michail Gouvalaris on April 17th, 2024. This script is intended for academic use at the Department of Informatics and Telecommunication, University of Ioannina.

## Requirements

- Python 3.12 or higher

## Features

- Calculates cryptographic hashes of files using MD5, SHA-1, SHA-256, and SHA3-256.
- Checks the integrity of files by comparing the calculated hashes at different times to detect modifications.
- Efficient processing of files in manageable chunks to handle large files without excessive memory usage.

## Installation

No additional installation is required, just ensure you have Python 3.12 or higher installed on your system.

## Usage

1. Ensure the file path in the script is set to the file you want to check.
2. Run the script to calculate the initial hashes of the file.
3. Store these hash values if you need to verify the file's integrity at a later time.
4. To check the integrity, re-run the script and compare the newly calculated hashes with the originally stored hashes.

### Example Code

```python
file_path = r"PATH"
original_hashes = calculate_hashes(file_path)
print("Original Hashes:", original_hashes)

# Later, to verify integrity
current_hashes = calculate_hashes(file_path)
integrity_check = check_integrity(original_hashes, current_hashes)
print("Integrity Check Results:", integrity_check)
