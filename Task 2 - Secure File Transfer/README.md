# Secure File Transfer Application

**Rhombix Technologies – Cyber Security Task 2**

A local demonstration application for secure file transfer using encryption, authentication, access control, integrity verification, and audit logging.

## Features

- User registration and password hashing
- Login/logout with session management
- File encryption using Fernet (authenticated symmetric encryption)
- Secure storage of encrypted file blobs
- SHA-256 integrity verification after decryption
- Sender/recipient access control
- Audit logs for login, upload, download, denied access, and failures
- 25 MB demonstration upload limit

## Technology

- Python 3
- Flask
- SQLite
- Cryptography (Fernet)
- HTML/CSS

## Run

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

Register two users, for example `alice` and `bob`. Login as Alice, upload a file for Bob, logout, login as Bob and download it.

## Security design

1. Passwords are stored as Werkzeug password hashes, not plaintext.
2. Uploaded file content is encrypted before being written to `data/encrypted_files`.
3. The application checks that the authenticated user is the sender or intended recipient before allowing a download.
4. SHA-256 is calculated on the original plaintext and checked again after decryption.
5. Audit events are stored in SQLite.
6. The Fernet key is stored separately from encrypted file blobs.

## Important production note

This is an internship demonstration, not a production-grade cloud service. For production deployment, use HTTPS/TLS, a managed secrets/key-management system, CSRF protection, rate limiting, secure cookie configuration, malware scanning, stronger authorization roles, encrypted backups, and a production WSGI server.
