# Intentionally Vulnerable Demo App
# DO NOT use this in production — it's designed to trigger SecurePipe findings

from flask import Flask, request, jsonify
import sqlite3
import os
import subprocess

app = Flask(__name__)

# 🚨 SECRETS: Hardcoded credentials (Gitleaks will flag these)
DB_PASSWORD = "super_secret_password_123"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
STRIPE_API_KEY = "sk_live_abc123def456"

@app.route("/")
def index():
    return "<h1>Vulnerable Demo App</h1><p>This app is intentionally insecure for testing SecurePipe.</p>"

# 🚨 SAST: SQL Injection
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection!
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return jsonify(result)

# 🚨 SAST: Command Injection
@app.route("/ping")
def ping():
    host = request.args.get("host")
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)  # Command injection!
    return result

# 🚨 SAST: Insecure deserialization
@app.route("/eval")
def eval_code():
    code = request.args.get("code")
    return str(eval(code))  # Remote code execution!

# 🚨 SAST: Weak cryptography
import hashlib
@app.route("/hash")
def hash_password():
    password = request.args.get("password")
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is broken!

if __name__ == "__main__":
    # 🚨 SAST: Debug mode in production
    app.run(host="0.0.0.0", debug=True)