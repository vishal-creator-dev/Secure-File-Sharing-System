import os
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, redirect, url_for, session, send_file, flash, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
STORAGE_DIR = os.path.join(BASE_DIR, "encrypted_storage")
KEY_FILE = os.path.join(BASE_DIR, "secret.key")

os.makedirs(STORAGE_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB demo limit

def get_fernet():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        return Fernet(f.read())

fernet = get_fernet()

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    );

    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        uploaded_by INTEGER NOT NULL,
        uploaded_at TEXT NOT NULL,
        FOREIGN KEY(uploaded_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS download_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        file_id INTEGER NOT NULL,
        created_by INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY(file_id) REFERENCES files(id),
        FOREIGN KEY(created_by) REFERENCES users(id)
    );
    """)

    admin = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("Admin@123"), "admin")
        )
    conn.commit()
    conn.close()

init_db()

def current_user():
    if "user_id" not in session:
        return None
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return user

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper

def can_access_file(user, file_row):
    return user["role"] == "admin" or file_row["uploaded_by"] == user["id"]

@app.context_processor
def inject_user():
    return {"current_user": current_user()}

@app.route("/")
def index():
    return redirect(url_for("dashboard")) if current_user() else redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(password) < 6:
            flash("Username must be 3+ characters and password 6+ characters.", "error")
            return render_template("register.html")

        conn = db()
        try:
            conn.execute(
                "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), "user")
            )
            conn.commit()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "error")
            return render_template("register.html")
        finally:
            conn.close()

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    conn = db()

    if user["role"] == "admin":
        rows = conn.execute("""
            SELECT files.*, users.username
            FROM files JOIN users ON files.uploaded_by = users.id
            ORDER BY files.id DESC
        """).fetchall()
    else:
        rows = conn.execute("""
            SELECT files.*, users.username
            FROM files JOIN users ON files.uploaded_by = users.id
            WHERE files.uploaded_by = ?
            ORDER BY files.id DESC
        """, (user["id"],)).fetchall()

    conn.close()
    return render_template("dashboard.html", files=rows)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files.get("file")

    if not uploaded or not uploaded.filename:
        flash("Select a file first.", "error")
        return redirect(url_for("dashboard"))

    original_name = os.path.basename(uploaded.filename)
    data = uploaded.read()

    if not data:
        flash("Empty files are not allowed.", "error")
        return redirect(url_for("dashboard"))

    stored_name = secrets.token_hex(16) + ".enc"
    encrypted = fernet.encrypt(data)

    with open(os.path.join(STORAGE_DIR, stored_name), "wb") as f:
        f.write(encrypted)

    user = current_user()
    conn = db()
    conn.execute("""
        INSERT INTO files(original_name, stored_name, uploaded_by, uploaded_at)
        VALUES (?, ?, ?, ?)
    """, (
        original_name,
        stored_name,
        user["id"],
        datetime.now(timezone.utc).isoformat()
    ))
    conn.commit()
    conn.close()

    flash("File uploaded and encrypted successfully.", "success")
    return redirect(url_for("dashboard"))

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    user = current_user()
    conn = db()
    file_row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not file_row or not can_access_file(user, file_row):
        conn.close()
        flash("You do not have permission to access this file.", "error")
        return redirect(url_for("dashboard"))

    path = os.path.join(STORAGE_DIR, file_row["stored_name"])
    if not os.path.exists(path):
        conn.close()
        flash("Encrypted file is missing.", "error")
        return redirect(url_for("dashboard"))

    with open(path, "rb") as f:
        decrypted = fernet.decrypt(f.read())

    temp_path = os.path.join(STORAGE_DIR, "tmp_" + secrets.token_hex(12))
    with open(temp_path, "wb") as f:
        f.write(decrypted)

    conn.close()

    response = send_file(
        temp_path,
        as_attachment=True,
        download_name=file_row["original_name"]
    )

    @response.call_on_close
    def cleanup():
        try:
            os.remove(temp_path)
        except OSError:
            pass

    return response

@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    user = current_user()
    conn = db()
    file_row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not file_row or not can_access_file(user, file_row):
        conn.close()
        flash("You do not have permission to delete this file.", "error")
        return redirect(url_for("dashboard"))

    path = os.path.join(STORAGE_DIR, file_row["stored_name"])
    if os.path.exists(path):
        os.remove(path)

    conn.execute("DELETE FROM download_tokens WHERE file_id = ?", (file_id,))
    conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()

    flash("File deleted.", "success")
    return redirect(url_for("dashboard"))

@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def create_share_link(file_id):
    user = current_user()
    try:
        minutes = int(request.form.get("minutes", "10"))
    except ValueError:
        minutes = 10

    minutes = max(1, min(minutes, 1440))

    conn = db()
    file_row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not file_row or not can_access_file(user, file_row):
        conn.close()
        flash("You do not have permission to share this file.", "error")
        return redirect(url_for("dashboard"))

    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(minutes=minutes)

    conn.execute("""
        INSERT INTO download_tokens(token, file_id, created_by, expires_at)
        VALUES (?, ?, ?, ?)
    """, (token, file_id, user["id"], expires.isoformat()))
    conn.commit()
    conn.close()

    share_url = url_for("temporary_download", token=token, _external=True)
    flash(f"Temporary link: {share_url} (expires in {minutes} minutes)", "success")
    return redirect(url_for("dashboard"))

@app.route("/temp-download/<token>")
def temporary_download(token):
    conn = db()
    row = conn.execute("""
        SELECT download_tokens.*, files.original_name, files.stored_name
        FROM download_tokens JOIN files ON download_tokens.file_id = files.id
        WHERE download_tokens.token = ?
    """, (token,)).fetchone()

    if not row:
        conn.close()
        return "Invalid download link.", 404

    expires = datetime.fromisoformat(row["expires_at"])
    if datetime.now(timezone.utc) >= expires:
        conn.execute("DELETE FROM download_tokens WHERE id = ?", (row["id"],))
        conn.commit()
        conn.close()
        return "This download link has expired.", 410

    path = os.path.join(STORAGE_DIR, row["stored_name"])
    if not os.path.exists(path):
        conn.close()
        return "File not found.", 404

    with open(path, "rb") as f:
        decrypted = fernet.decrypt(f.read())

    temp_path = os.path.join(STORAGE_DIR, "shared_" + secrets.token_hex(12))
    with open(temp_path, "wb") as f:
        f.write(decrypted)

    conn.close()

    response = send_file(
        temp_path,
        as_attachment=True,
        download_name=row["original_name"]
    )

    @response.call_on_close
    def cleanup():
        try:
            os.remove(temp_path)
        except OSError:
            pass

    return response

@app.route("/admin/users")
@admin_required
def users():
    conn = db()
    rows = conn.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    conn.close()
    return render_template("users.html", users=rows)

@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def change_role(user_id):
    role = request.form.get("role")
    if role not in ("admin", "user"):
        flash("Invalid role.", "error")
        return redirect(url_for("users"))

    conn = db()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    conn.commit()
    conn.close()
    flash("Role updated.", "success")
    return redirect(url_for("users"))

if __name__ == "__main__":
    app.run(debug=True)
