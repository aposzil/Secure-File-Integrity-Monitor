# Secure File Integrity Monitor (SFIM) v26 - Full Encryption Edition

A cross-platform (Windows/Linux) command-line tool written in Python to monitor file integrity using cryptographic hashes and local encrypted storage. 

## 🛡️ Key Features
- **AES-256 Encryption**: Protects the local integrity database using the [Fernet](https://cryptography.io) symmetric encryption standard.
- **PBKDF2 Key Derivation**: Derives encryption keys from user passwords using 100,000 iterations of SHA-256 and a unique salt.
- **Full Cryptographic Metadata Protection**: Unlike previous versions, app.meta and backups are now fully encrypted. The tool verifies its own integrity by decrypting and validating system snapshots only after successful user authentication.
- **Stealth Mode**: Automatically hides sensitive system files (`.dat`, `.salt`, `.meta`, `.bak`) using OS-specific attributes (Hidden flag on Windows, dot-prefix on Linux).
- **Intelligent Sorting**: Displays scan results prioritized by status: `ATTENTION` > `CHANGED` > `OK`.
- **Automated Recovery**: Built-in backup and recovery system to restore the database from a verified state.

## 🚀 Technical Implementation
- **Hashing**: Implements **SHA-256** for file fingerprinting, ensuring collision resistance.
- **Security**: Utilizes the `getpass` library to prevent password shoulder-surfing during authentication.
- **Persistence**: Maintains file status (`OK`, `CHANGED`, `ATTENTION`) and timestamps for auditing.

## 🛠️ Requirements
- Python 3.x
- [Cryptography](https://pypi.org) library: `pip install cryptography`
- [Requests](https://pypi.org) library: `pip install requests`

## 📖 Usage
1. Clone the repository: `git clone https://github.com`
2. Run the script: `python Hash_Checker.py`
3. On first run, create your master password and perform an initial scan.
4. **Important**: Always use the **Exit (5)** option to securely update the self-integrity snapshot.

## 📁 System Files
- `integrity_vault.dat`: Encrypted database of file hashes.
- `user.salt`: Unique salt for key derivation.
- `app.meta`: Encrypted integrity snapshot of the tool's assets.
- `integrity_vault.bak`: Encrypted last verified backup.

## ⚠️ Disclaimer
This tool is intended for personal file monitoring. Ensure you remember your master password; due to the PBKDF2 implementation, there is no way to recover encrypted data without it.
