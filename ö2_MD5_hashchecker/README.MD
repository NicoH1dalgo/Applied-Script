# MD5 Hash Checker with Python and Hashcat

## Description
This project demonstrates password hashing vulnerabilities and cracking techniques. It includes a Python script that generates random numeric passwords and their MD5 hashes, and a bash script that uses Hashcat to crack them using brute-force mask attacks.

## Purpose
- Test rainbow table limitations by finding the password length threshold
- Generate MD5 hashes beyond rainbow table coverage
- Practice password cracking with Hashcat mask attacks
- Understand hash security and cracking techniques

## Files
- `md5-hasher.py` - Generates 10 random numeric passwords and their MD5 hashes
- `md5-hashcat.sh` - Bash script to crack MD5 hashes using Hashcat with mask attacks
- `screenshot.png` - Hashcat results showing successful cracking

## Usage
```bash