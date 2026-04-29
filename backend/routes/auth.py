from routes.threat_check import (
    check_suspicious_ip,
    check_off_hours,
    check_concurrent_session
)

from datetime import datetime
import secrets
import bcrypt
from flask import Blueprint, request, render_template, make_response, redirect
from db import query

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/auth/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    ip = request.remote_addr
    device = request.headers.get("User-Agent", "Unknown")

    # Task 3 — look up user
    rows = query(
        "SELECT * FROM users WHERE username = %s",
        (username,)
    )

    if not rows:
        return render_template("login.html", error="Invalid credentials")

    user = rows[0]

    # Task 4 — check password
    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        query(
            """INSERT INTO events
               (event_type, user_id, ip_address, success, asset_id, session_id)
               VALUES ('login_failed', %s, %s, false, 1, 1)""",
            (user["user_id"], ip)
        )

        return render_template("login.html", error="Invalid credentials")

    # Task 5 — create session
    token = secrets.token_hex(32)

    session_rows = query(
        """INSERT INTO sessions
           (user_id, org_id, session_token, ip_address, device_info, login_time, sta_tus)
           VALUES (%s, %s, %s, %s, %s, NOW(), 'Active')
           RETURNING session_id""",
        (user["user_id"], user["org_id"], token, ip, device)
    )

    session_id = session_rows[0]["session_id"]

    # Create login success event and get event_id
    event_rows = query(
        """INSERT INTO events
           (event_type, user_id, session_id, ip_address, success, asset_id)
           VALUES ('login_success', %s, %s, %s, true, 1)
           RETURNING event_id""",
        (user["user_id"], session_id, ip)
    )

    event_id = event_rows[0]["event_id"]

    # Threat checks
    check_suspicious_ip(user["user_id"], ip, session_id, event_id)
    check_off_hours(user["user_id"], event_id, datetime.now())
    check_concurrent_session(user["user_id"], ip, event_id)

    # Task 6 — set cookie and redirect based on role
    if user["role_id"] == 1:
        resp = make_response(redirect("/sessions"))
    else:
        resp = make_response(redirect(f"/welcome?username={username}"))

    resp.set_cookie("session_token", token)
    return resp


@auth_bp.route("/auth/logout", methods=["POST"])
def logout():
    token = request.cookies.get("session_token")

    if token:
        query(
            """UPDATE sessions
               SET logout_time = NOW(),
                   sta_tus = 'Expired'
               WHERE session_token = %s""",
            (token,)
        )

    resp = make_response(redirect("/auth/login"))
    resp.delete_cookie("session_token")
    return resp


@auth_bp.route("/welcome")
def welcome():
    username = request.args.get("username", "User")
    return render_template("welcome.html", username=username)
