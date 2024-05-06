# CITS2006

## Planned Structure of Dependencies
Yara -> Rules.yar + Hash
Cipher -> None
File(Hash and Cipher) -> Cipher + Hash
MTD -> Yara + File

## Flow
main ->  
- Check Filesystem Integrity with Stored Hashes
- Launch Periodic File Scan Async
- Runs MTD
- Output Security Recommendations

login ->
- Asks user for key in form of password (auth pass+salt compare with hash, use stored keypair separate from user pass)
- Decrypts Files, keep track of "user logon"
- Encrypts File on log out, or after a set period of time.
- Keep track of hash changes within user's directory.
  


Cipher:
1/5/2024 - Added XOR encryption

5/5/2024 -Added RSA & Basee64 encryption
