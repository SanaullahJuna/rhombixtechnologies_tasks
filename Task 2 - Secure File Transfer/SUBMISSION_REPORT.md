# Rhombix Technologies — Cyber Security Task 2
## Secure File Transfer Application

### 1. Objective
Develop a secure file transfer application that protects transferred files using encryption and implements confidentiality, integrity, access controls and audit logs.

### 2. Implemented Security Controls
- End-to-end style application-layer encryption using Fernet authenticated encryption.
- Password hashing using Werkzeug.
- Authentication through login sessions.
- Authorization: only the sender or intended recipient can download a file.
- Integrity: SHA-256 digest is calculated before encryption and verified after decryption.
- Audit logging for authentication, uploads, downloads, denied access and security failures.
- Encrypted file blobs are stored separately from the application database.
- Original filenames are sanitized before storage/serving.

### 3. User Workflow
1. Register two users.
2. Log in as the sender.
3. Select a recipient and file.
4. The application calculates SHA-256 and encrypts the file before storing it.
5. The recipient logs in.
6. The recipient downloads the file.
7. The application decrypts it, verifies SHA-256, and returns the original file.
8. The event is recorded in the audit log.

### 4. Testing Checklist
- [ ] Register user A.
- [ ] Register user B.
- [ ] Login as user A.
- [ ] Send a small text/PDF/image file to user B.
- [ ] Confirm the application reports successful encryption/upload.
- [ ] Logout and login as user B.
- [ ] Download the file.
- [ ] Open the downloaded file and verify it matches the original.
- [ ] Verify audit logs contain upload and download events.
- [ ] Test that a third user cannot access another user's file by changing the file ID in the URL.

### 5. Security Notes
The project is an internship demonstration. Production deployment should additionally use HTTPS/TLS, CSRF protection, rate limiting, secure cookies, a managed key-management service, malware scanning, stronger role-based access control, encrypted backups, and a production WSGI server.

### 6. Repository
Recommended GitHub repository name:
`RhombixTechnologies_Tasks`

Place this project inside a suitable task folder, for example:
`CyberSecurity/Task2_SecureFileTransfer/`
