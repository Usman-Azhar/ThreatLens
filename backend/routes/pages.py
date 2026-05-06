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
        WHERE u.org_id = %s
        ORDER BY s.login_time DESC
    """, (user["org_id"],))
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
        WHERE u.org_id = %s
        ORDER BY e.times_tamp DESC
    """, (user["org_id"],))
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
        WHERE u.org_id = %s
        ORDER BY al.created_at DESC
    """, (user["org_id"],))
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

    org_id = user["org_id"]

    events_per_day = query("""
        SELECT DATE(e.times_tamp) as day, COUNT(*) as count
        FROM events e
        JOIN users u ON e.user_id = u.user_id
        WHERE u.org_id = %s
        GROUP BY day ORDER BY day
    """, (org_id,))

    severity_breakdown = query("""
        SELECT al.severity, COUNT(*) as count
        FROM alerts al
        JOIN events e ON al.event_id = e.event_id
        JOIN users u  ON e.user_id   = u.user_id
        WHERE u.org_id = %s
        GROUP BY al.severity
    """, (org_id,))

    alert_types = query("""
        SELECT al.alert_type, COUNT(*) as count
        FROM alerts al
        JOIN events e ON al.event_id = e.event_id
        JOIN users u  ON e.user_id   = u.user_id
        WHERE u.org_id = %s
        GROUP BY al.alert_type
    """, (org_id,))

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


# ── USER MANAGEMENT (Admin only) ─────────────────────────────────────────────

@pages_bp.route("/users")
def users_page():
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/auth/login")
    user = get_current_user(token)
    if not user:
        return redirect("/auth/login")
    if user["role_id"] != 1:
        log_unauthorized(user, "/users")
        return redirect("/welcome")
    rows = query("""
        SELECT u.user_id, u.username, u.email, u.role_id, r.role_name,
               u.created_at, u.is_active
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        WHERE u.org_id = %s
        ORDER BY u.user_id
    """, (user["org_id"],))
    roles = query("SELECT role_id, role_name FROM roles ORDER BY role_id")
    return render_template("users.html", users=rows, roles=roles,
                           role_id=user["role_id"], current_user_id=user["user_id"])


@pages_bp.route("/users/<int:target_id>/role", methods=["POST"])
def change_role(target_id):
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/auth/login")
    user = get_current_user(token)
    if not user or user["role_id"] != 1:
        return redirect("/welcome")
    new_role = request.form.get("role_id")
    if new_role not in ("1", "2", "3"):
        return redirect("/users")
    # Admin cannot change their own role
    if target_id == user["user_id"]:
        return redirect("/users")
    query("""
        UPDATE users SET role_id = %s
        WHERE user_id = %s AND org_id = %s
    """, (new_role, target_id, user["org_id"]))
    return redirect("/users")


@pages_bp.route("/users/<int:target_id>/toggle", methods=["POST"])
def toggle_user(target_id):
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/auth/login")
    user = get_current_user(token)
    if not user or user["role_id"] != 1:
        return redirect("/welcome")
    # Admin cannot deactivate themselves
    if target_id == user["user_id"]:
        return redirect("/users")
    query("""
        UPDATE users SET is_active = NOT is_active
        WHERE user_id = %s AND org_id = %s
    """, (target_id, user["org_id"]))
    return redirect("/users")


# ── THREAT INTELLIGENCE MANAGEMENT (Admin only) ──────────────────────────────

@pages_bp.route("/threat-intel")
def threat_intel_page():
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/auth/login")
    user = get_current_user(token)
    if not user:
        return redirect("/auth/login")
    if user["role_id"] != 1:
        log_unauthorized(user, "/threat-intel")
        return redirect("/welcome")
    rows = query("""
        SELECT threat_id, threat_type, value, last_updated
        FROM threat_intelligence
        ORDER BY last_updated DESC
    """)
    return render_template("threat_intel.html", threats=rows, role_id=user["role_id"])


@pages_bp.route("/threat-intel/add", methods=["POST"])
def threat_intel_add():
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/auth/login")
    user = get_current_user(token)
    if not user or user["role_id"] != 1:
        return redirect("/welcome")
    threat_type = request.form.get("threat_type")
    value       = request.form.get("value", "").strip()
    if threat_type not in ("malicious_ip", "tor_exit_node", "known_attacker"):
        return redirect("/threat-intel")
    if not value:
        return redirect("/threat-intel")
    query("""
        INSERT INTO threat_intelligence (threat_type, value, last_updated)
        VALUES (%s, %s, NOW())
    """, (threat_type, value))
    return redirect("/threat-intel")


@pages_bp.route("/threat-intel/<int:threat_id>/delete", methods=["POST"])
def threat_intel_delete(threat_id):
    token = request.cookies.get("session_token")
    if not token:
        return redirect("/auth/login")
    user = get_current_user(token)
    if not user or user["role_id"] != 1:
        return redirect("/welcome")
    query("DELETE FROM threat_intelligence WHERE threat_id = %s", (threat_id,))
    return redirect("/threat-intel")