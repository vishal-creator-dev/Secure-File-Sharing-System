# Secure File Sharing System

A college-project implementation of **Task 5: Secure File Sharing System** using Python, Flask, SQLite and Fernet encryption.

## Features

- User registration and login
- Password hashing
- Authenticated upload/download
- AES-based Fernet encryption before server storage
- Role-Based Access Control (Admin/User)
- Admin can view all files and manage user roles
- Temporary download links with expiration
- SQLite database
- 25 MB upload limit for demonstration

## Default Admin

Username: `admin`  
Password: `Admin@123`

**Change the default admin password before real deployment.**

## How to run

### 1. Create a virtual environment

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the application

```bash
python app.py
```

Open:

`http://127.0.0.1:5000`

## Project flow

1. User registers.
2. User logs in.
3. User uploads a file.
4. Application encrypts the file using Fernet before saving it.
5. Only authorized users can download it.
6. Owner/Admin can generate a temporary link.
7. Temporary link automatically becomes invalid after its expiry time.

## Project structure

```text
secure_file_sharing_system/
│
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── users.html
└── encrypted_storage/
```

`database.db` and `secret.key` are generated automatically on first run.

## Security note

This is designed for a college demonstration/project. For production, add HTTPS, CSRF protection, rate limiting, secure cookie configuration, antivirus/file-type validation, stronger secret management, audit logging and a production WSGI server.
