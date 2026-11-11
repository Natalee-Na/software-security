
"""
Hardened sample for Week 2 security remediation.
"""
import os
import sqlite3
import subprocess
import bcrypt
from flask import Flask, request

app = Flask(__name__)

# CWE-798: Load secrets from environment variables
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]


@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    # CWE-89: Use a parameterized SQL query
    q = "SELECT * FROM users WHERE name = ?"
    result = con.execute(q, (name,)).fetchall()
    con.close()
    return str(result)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78: Pass arguments as a list; do not use shell=True
    return subprocess.check_output(["ping", "-c", "1", host])


def store_password(pw):
    # CWE-327: Use bcrypt instead of MD5
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_password(pw, hashed):
    return bcrypt.checkpw(pw.encode(), hashed.encode())


if __name__ == "__main__":
    # CWE-489: Disable debug mode
    app.run(debug=False)
