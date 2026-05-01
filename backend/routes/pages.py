from flask import Blueprint, render_template, request, redirect
from db import query, get_current_user
from routes.threat_check import check_unauthorized_access

pages_bp = Blueprint("pages", __name__)


def log_unauthorized(user, route):
    ip = request.remote_addr
    row = query(
        """INSERT INTO events
               (user_id, asset_id, session_id, event_type, ip_address, success)
           VALUES (%s, 1, %s, 'page_access', %s, FALSE)
           RETURNING event_id""",
        (user["user_id"], user["session_id"], ip)
    )
    event_id = row[0]["event_id"]
    check_unauthorized_access(user["user_id"], user["session_id"], event_id, route)


@pages_bp.route("/sessions")
def sessions_page():
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/auth/login")
    user = get_current_user(token)
    if not user:
        return redirect("/auth/login")
    if user["role_id"] != 1:
        log_unauthorized(user, "/sessions")
        return redirect("/welcome")
    rows = query("""
        SELECT s.session_id, u.username, s.ip_address, s.device_info,
               s.login_time, s.last_active, s.logout_time, s.sta_tus, s.is_flagged
        FROM sessions s
        JOIN users u ON s.user_id = u.user_id
        ORDER BY s.login_time DESC
    """)
    return render_template("sessions.html", sessions=rows, role_id=user["role_id"])


@pages_bp.route("/events")
def events_page():
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/auth/login")
    user = get_current_user(token)
    if not user:
        return redirect("/auth/login")
    if user["role_id"] not in (1, 2):
        log_unauthorized(user, "/events")
        return redirect("/welcome")
    rows = query("""
        SELECT e.event_id, u.username, a.asset_name, e.event_type,
               e.ip_address, e.success, e.times_tamp, e.metadata
        FROM events e
        JOIN users u  ON e.user_id  = u.user_id
        JOIN assets a ON e.asset_id = a.asset_id
        ORDER BY e.times_tamp DESC
    """)
    return render_template("events.html", events=rows, role_id=user["role_id"])


@pages_bp.route("/alerts")
def alerts_page():
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/auth/login")
    user = get_current_user(token)
    if not user:
        return redirect("/auth/login")
    if user["role_id"] not in (1, 2):
        log_unauthorized(user, "/alerts")
        return redirect("/welcome")
    rows = query("""
        SELECT al.alert_id, al.alert_type, al.severity, al.sta_tus,
               al.created_at, e.event_type, u.username, e.ip_address
        FROM alerts al
        JOIN events e ON al.event_id = e.event_id
        JOIN users u  ON e.user_id   = u.user_id
        ORDER BY al.created_at DESC
    """)
    return render_template("alerts.html", alerts=rows, role_id=user["role_id"])


@pages_bp.route("/stats")
def stats_page():
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/auth/login")
    user = get_current_user(token)
    if not user:
        return redirect("/auth/login")
    if user["role_id"] not in (1, 2):
        log_unauthorized(user, "/stats")
        return redirect("/welcome")
    events_per_day = query("""
        SELECT DATE(e.times_tamp) as day, COUNT(*) as count
        FROM events e
        JOIN users u ON e.user_id = u.user_id
        GROUP BY day ORDER BY day
    """)
    severity_breakdown = query("""
        SELECT al.severity, COUNT(*) as count
        FROM alerts al
        JOIN events e ON al.event_id = e.event_id
        JOIN users u  ON e.user_id   = u.user_id
        GROUP BY al.severity
    """)
    alert_types = query("""
        SELECT al.alert_type, COUNT(*) as count
        FROM alerts al
        JOIN events e ON al.event_id = e.event_id
        JOIN users u  ON e.user_id   = u.user_id
        GROUP BY al.alert_type
    """)
    return render_template("stats.html",
        events_per_day=events_per_day,
        severity_breakdown=severity_breakdown,
        alert_types=alert_types,
        role_id=user["role_id"])


@pages_bp.route("/welcome")
def welcome_page():
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/auth/login")
    user = get_current_user(token)
    if not user:
        return redirect("/auth/login")
    return render_template("welcome.html",
        username=user["username"],
        org_name=user["org_name"])