from flask import Flask, render_template, request
import re
import sqlite3
from datetime import datetime

app = Flask(__name__)

# -----------------------------
# DATABASE INITIALIZATION
# -----------------------------
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    # Scan history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            risk_score INTEGER,
            result TEXT,
            scan_time TEXT
        )
    """)

    # Blacklist table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            added_date TEXT
        )
    """)
    
    conn.commit()
    conn.close()

init_db()


# -----------------------------
# PHISHING DETECTION LOGIC
# -----------------------------
def check_url(url):
    score = 0

    # Extract domain
    domain = url.replace("http://", "").replace("https://", "").split("/")[0]

    # Check blacklist first
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blacklist WHERE domain = ?", (domain,))
    blacklisted = cursor.fetchone()
    conn.close()

    if blacklisted:
        return 10, "❌ Phishing (Blacklisted Domain)"

    # Check IP address
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        score += 2

    # Check URL length
    if len(url) > 75:
        score += 1

    # Suspicious keywords
    suspicious_words = ["login", "verify", "update", "secure", "account"]
    for word in suspicious_words:
        if word in url.lower():
            score += 1

    if score >= 3:
        result = "⚠️ Suspicious (Possible Phishing)"
    else:
        result = "✅ Likely Safe"

    return score, result

# -----------------------------
# SIMPLE LOGIN PAGE
# -----------------------------
from flask import redirect, url_for, session

# Secret key for session management
app.secret_key = "supersecretkey123"  # change to a random string in production

# Hardcoded username/password
USERNAME = "admin"
PASSWORD = "password123"

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == USERNAME and password == PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("home"))
        else:
            error = "❌ Invalid credentials. Try again."

    return render_template("login.html", error=error)


# -----------------------------
# HOME PAGE
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    
    if request.method == "POST":
        url = request.form["url"]
        score, result = check_url(url)

        # Save scan result
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history (url, risk_score, result, scan_time)
            VALUES (?, ?, ?, ?)
        """, (url, score, result, datetime.now()))
        
        conn.commit()
        conn.close()

    return render_template("index.html", result=result)


# -----------------------------
# HISTORY PAGE
# -----------------------------
@app.route("/history")
def history():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT url, risk_score, result, scan_time FROM scan_history ORDER BY id DESC")
    data = cursor.fetchall()
    conn.close()

    return render_template("history.html", data=data)


# -----------------------------
# ADD TO BLACKLIST (ADMIN)
# -----------------------------
@app.route("/add_blacklist", methods=["POST"])
def add_blacklist():
    domain = request.form["domain"]

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO blacklist (domain, added_date)
        VALUES (?, ?)
    """, (domain, datetime.now()))

    conn.commit()
    conn.close()

    return "Domain added to blacklist successfully!"

# -----------------------------
# ADMIN PANEL PAGE
# -----------------------------
@app.route("/admin")
def admin():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT domain, added_date FROM blacklist ORDER BY id DESC")
    data = cursor.fetchall()
    conn.close()

    return render_template("admin.html", data=data)

# -----------------------------
# RUN APP
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)