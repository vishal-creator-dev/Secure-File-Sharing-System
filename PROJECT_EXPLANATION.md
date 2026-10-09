# Task 5 – Project Explanation / Viva

## 1. What is the project?
A web application that allows authenticated users to upload and download files securely.

## 2. Why encryption?
If someone gets access to the server's storage folder, the stored files are encrypted and cannot be read as normal files.

## 3. Authentication
Passwords are not stored directly. Werkzeug's password hashing stores a password hash.

## 4. RBAC
Two roles are implemented:
- Admin: can manage users and access all files.
- User: can access files uploaded by that user.

## 5. Temporary links
The system creates a random token and stores an expiry timestamp. The link works only until the expiry time.

## 6. Technologies
- Python
- Flask
- SQLite
- Cryptography/Fernet
- HTML/CSS

## 7. Demo sequence
1. Run `python app.py`.
2. Login as `admin` using `Admin@123`.
3. Register another normal user.
4. Upload a file.
5. Download it.
6. Show the `encrypted_storage` folder to demonstrate that the stored file is `.enc`.
7. Generate a temporary link for 1 minute.
8. Open the link and show that it downloads the decrypted original file.
9. Use Admin > Users to demonstrate role-based access.

## 8. Main security features
Authentication + password hashing + encryption at rest + authorization/RBAC + expiring random download tokens.
