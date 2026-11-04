import os
import secrets
import sqlite3
from datetime import date
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
DB_PATH = os.environ.get("LIKES_DB_PATH", "daily_likes.sqlite3")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS daily_likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT NOT NULL,
            region TEXT NOT NULL DEFAULT 'IND',
            likes INTEGER NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    return conn


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return jsonify({"error": "Authentication required"}), 401
        return fn(*args, **kwargs)
    return wrapper


@app.get("/")
def home():
    return redirect(url_for("admin_page"))


@app.route("/admin", methods=["GET", "POST"])
def admin_page():
    if request.method == "POST":
        stored_hash = os.environ.get("ADMIN_PASSWORD_HASH", "")
        password = request.form.get("password", "")
        if not stored_hash or not check_password_hash(stored_hash, password):
            return render_template("admin.html", logged_in=False, error="Invalid login or server password is not configured."), 401
        session.clear()
        session["admin"] = True
        session["csrf"] = secrets.token_urlsafe(32)
        return redirect(url_for("admin_page"))
    return render_template("admin.html", logged_in=bool(session.get("admin")), csrf=session.get("csrf", ""), error="")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("admin_page"))


@app.get("/api/summary")
@admin_required
def summary():
    today = date.today().isoformat()
    with db() as conn:
        today_row = conn.execute(
            "SELECT COALESCE(SUM(likes),0) AS likes, COUNT(*) AS entries FROM daily_likes WHERE date(created_at)=?",
            (today,)
        ).fetchone()
        total = conn.execute("SELECT COALESCE(SUM(likes),0) AS likes FROM daily_likes").fetchone()
        recent = conn.execute(
            "SELECT uid, region, likes, note, created_at FROM daily_likes ORDER BY id DESC LIMIT 30"
        ).fetchall()
    return jsonify({
        "date": today,
        "today_likes": today_row["likes"],
        "today_entries": today_row["entries"],
        "all_time_likes": total["likes"],
        "recent": [dict(row) for row in recent]
    })


@app.post("/api/records")
@admin_required
def add_record():
    if request.headers.get("X-CSRF-Token") != session.get("csrf"):
        return jsonify({"error": "Invalid request token"}), 403
    data = request.get_json(silent=True) or {}
    uid = str(data.get("uid", "")).strip()
    likes = data.get("likes")
    note = str(data.get("note", "")).strip()[:160]
    if not uid.isdigit() or not (5 <= len(uid) <= 15):
        return jsonify({"error": "UID must contain 5–15 digits"}), 400
    if isinstance(likes, bool) or not isinstance(likes, int) or not (0 <= likes <= 1000000):
        return jsonify({"error": "Likes must be a whole number from 0 to 1,000,000"}), 400
    with db() as conn:
        conn.execute(
            "INSERT INTO daily_likes (uid, region, likes, note) VALUES (?, 'IND', ?, ?)",
            (uid, likes, note)
        )
    return jsonify({"ok": True})


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "IND daily likes tracker"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=False)
