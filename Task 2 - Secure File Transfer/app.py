import os
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, redirect, url_for, render_template, session, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "encrypted_files")
DB_PATH = os.path.join(DATA_DIR, "app.db")
KEY_PATH = os.path.join(DATA_DIR, "master.key")

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB demo limit

def get_fernet():
    if not os.path.exists(KEY_PATH):
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as f:
            f.write(key)
        try:
            os.chmod(KEY_PATH, 0o600)
        except OSError:
            pass
    with open(KEY_PATH, "rb") as f:
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
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id),
        FOREIGN KEY(recipient_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        file_id INTEGER,
        details TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(file_id) REFERENCES files(id)
    );
    """)
    conn.commit()
    conn.close()

def log_event(user_id, action, file_id=None, details=""):
    conn = db()
    conn.execute(
        "INSERT INTO audit_logs(user_id, action, file_id, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, action, file_id, details, datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(password) < 8:
            flash("Username must be 3+ characters and password 8+ characters.")
            return redirect(url_for("register"))
        conn = db()
        try:
            conn.execute(
                "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
            flash("Registration successful. Please login.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
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
            session["username"] = user["username"]
            log_event(user["id"], "LOGIN_SUCCESS", details="User authenticated")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    uid = session["user_id"]
    log_event(uid, "LOGOUT")
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["user_id"]
    conn = db()
    sent = conn.execute("""
        SELECT f.*, u.username AS recipient
        FROM files f JOIN users u ON u.id=f.recipient_id
        WHERE f.owner_id=? ORDER BY f.id DESC
    """, (uid,)).fetchall()
    received = conn.execute("""
        SELECT f.*, u.username AS sender
        FROM files f JOIN users u ON u.id=f.owner_id
        WHERE f.recipient_id=? ORDER BY f.id DESC
    """, (uid,)).fetchall()
    users = conn.execute("SELECT id, username FROM users WHERE id != ? ORDER BY username", (uid,)).fetchall()
    logs = conn.execute("""
        SELECT a.*, f.original_name
        FROM audit_logs a LEFT JOIN files f ON f.id=a.file_id
        WHERE a.user_id=? ORDER BY a.id DESC LIMIT 20
    """, (uid,)).fetchall()
    conn.close()
    return render_template("dashboard.html", sent=sent, received=received, users=users, logs=logs)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    recipient_id = request.form.get("recipient_id")
    if not file or not file.filename:
        flash("Choose a file.")
        return redirect(url_for("dashboard"))
    if not recipient_id or not recipient_id.isdigit():
        flash("Choose a valid recipient.")
        return redirect(url_for("dashboard"))

    original = secure_filename(file.filename)
    if not original:
        flash("Invalid filename.")
        return redirect(url_for("dashboard"))

    raw = file.read()
    if not raw:
        flash("Empty files are not allowed.")
        return redirect(url_for("dashboard"))

    # Integrity value is calculated over the plaintext before encryption.
    import hashlib
    digest = hashlib.sha256(raw).hexdigest()

    encrypted = fernet.encrypt(raw)
    stored_name = secrets.token_hex(16) + ".bin"
    path = os.path.join(UPLOAD_DIR, stored_name)
    with open(path, "wb") as f:
        f.write(encrypted)

    conn = db()
    recipient = conn.execute("SELECT id, username FROM users WHERE id=?", (int(recipient_id),)).fetchone()
    if not recipient:
        conn.close()
        os.remove(path)
        flash("Recipient does not exist.")
        return redirect(url_for("dashboard"))

    cur = conn.execute("""
        INSERT INTO files(owner_id, recipient_id, original_name, stored_name, sha256, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (session["user_id"], recipient["id"], original, stored_name, digest, datetime.now(timezone.utc).isoformat()))
    file_id = cur.lastrowid
    conn.commit()
    conn.close()

    log_event(session["user_id"], "FILE_UPLOAD", file_id, f"Encrypted file sent to {recipient['username']}")
    flash("File encrypted and uploaded successfully.")
    return redirect(url_for("dashboard"))

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    uid = session["user_id"]
    conn = db()
    row = conn.execute("""
        SELECT f.*, u.username AS sender, r.username AS recipient
        FROM files f
        JOIN users u ON u.id=f.owner_id
        JOIN users r ON r.id=f.recipient_id
        WHERE f.id=?
    """, (file_id,)).fetchone()
    conn.close()

    if not row:
        abort(404)

    # Access control: only sender or intended recipient may download.
    if uid not in (row["owner_id"], row["recipient_id"]):
        log_event(uid, "ACCESS_DENIED", file_id, "Unauthorized download attempt")
        abort(403)

    path = os.path.join(UPLOAD_DIR, row["stored_name"])
    if not os.path.exists(path):
        abort(404)

    try:
        with open(path, "rb") as f:
            encrypted = f.read()
        plaintext = fernet.decrypt(encrypted)
    except InvalidToken:
        log_event(uid, "INTEGRITY_OR_DECRYPTION_FAILURE", file_id, "Ciphertext could not be decrypted")
        abort(500)

    import hashlib
    actual = hashlib.sha256(plaintext).hexdigest()
    if actual != row["sha256"]:
        log_event(uid, "INTEGRITY_CHECK_FAILED", file_id, "SHA-256 mismatch")
        abort(500)

    log_event(uid, "FILE_DOWNLOAD", file_id, f"Integrity verified; downloaded {row['original_name']}")
    temp_path = os.path.join(DATA_DIR, "download_" + secrets.token_hex(8) + "_" + row["original_name"])
    with open(temp_path, "wb") as f:
        f.write(plaintext)

    response = send_file(temp_path, as_attachment=True, download_name=row["original_name"])
    @response.call_on_close
    def cleanup():
        try:
            os.remove(temp_path)
        except OSError:
            pass
    return response

@app.route("/admin/logs")
@login_required
def logs():
    # Demo/admin view: only the user can view logs of actions associated with their account.
    conn = db()
    rows = conn.execute("""
        SELECT a.*, u.username, f.original_name
        FROM audit_logs a
        LEFT JOIN users u ON u.id=a.user_id
        LEFT JOIN files f ON f.id=a.file_id
        WHERE a.user_id=? ORDER BY a.id DESC
    """, (session["user_id"],)).fetchall()
    conn.close()
    return render_template("logs.html", logs=rows)

if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="127.0.0.1", port=5000)
