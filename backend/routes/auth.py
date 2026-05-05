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

    # check if user exists
    rows = query(
        "SELECT * FROM users WHERE username = %s",
        (username,)
    )

    if not rows:
        return render_template("login.html", error="Invalid credentials")

    user = rows[0]

    # grab the web app asset for this user's org (needed for event logging)
    asset_rows = query(
        "SELECT asset_id FROM assets WHERE org_id = %s AND asset_type = 'Web Application' LIMIT 1",
        (user["org_id"],)
    )
    asset_id = asset_rows[0]["asset_id"] if asset_rows else 1

    # verify password
    try:
        password_valid = bcrypt.checkpw(password.encode(), user["password_hash"].encode())
    except ValueError:
        return render_template("login.html", error="Invalid credentials")

    # wrong password — log the failed attempt and bail
    if not password_valid:
        query(
            """INSERT INTO events
               (event_type, user_id, ip_address, success, asset_id, session_id)
               VALUES ('login_failed', %s, %s, false, %s, NULL)""",
            (user["user_id"], ip, asset_id)
        )
        return render_template("login.html", error="Invalid credentials")

    # password is good — generate session token
    token = secrets.token_hex(32)

    # create the session in DB
    session_rows = query(
        """INSERT INTO sessions
           (user_id, org_id, session_token, ip_address, device_info, login_time, sta_tus)
           VALUES (%s, %s, %s, %s, %s, NOW(), 'Active')
           RETURNING session_id""",
        (user["user_id"], user["org_id"], token, ip, device)
    )

    session_id = session_rows[0]["session_id"]

    # log the successful login as an event
    event_rows = query(
        """INSERT INTO events
           (event_type, user_id, session_id, ip_address, success, asset_id)
           VALUES ('login_success', %s, %s, %s, true, %s)
           RETURNING event_id""",
        (user["user_id"], session_id, ip, asset_id)
    )

    event_id = event_rows[0]["event_id"]

    # run threat checks against this login
    check_suspicious_ip(user["user_id"], ip, session_id, event_id)
    check_off_hours(user["user_id"], event_id, datetime.now())
    check_concurrent_session(user["user_id"], ip, event_id)

    # redirect based on role — 1: admin, 2: analyst, else: regular user
    if user["role_id"] == 1:
        redirect_url = "/sessions"
    elif user["role_id"] == 2:
        redirect_url = "/alerts"
    else:
        redirect_url = "/welcome"

    resp = make_response(redirect(redirect_url))
    resp.set_cookie("session_token", token)
    return resp


@auth_bp.route("/auth/logout", methods=["POST"])
def logout():
    token = request.cookies.get("session_token")

    # expire the session in DB if token exists
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