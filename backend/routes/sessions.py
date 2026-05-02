from flask import Blueprint, jsonify, request
from db import query

sessions_bp = Blueprint("sessions", __name__)


# GET /api/sessions?org_id=1
@sessions_bp.route("/", methods=["GET"])
def get_sessions():
    org_id = request.args.get("org_id")
    if org_id:
        rows = query("""
            SELECT s.session_id, u.username, s.ip_address, s.device_info,
                   s.login_time, s.last_active, s.logout_time,
                   s.sta_tus, s.is_flagged
            FROM sessions s
            JOIN users u ON s.user_id = u.user_id
            WHERE s.org_id = %s
            ORDER BY s.login_time DESC
        """, (org_id,))
    else:
        rows = query("""
            SELECT s.session_id, u.username, s.ip_address, s.device_info,
                   s.login_time, s.last_active, s.logout_time,
                   s.sta_tus, s.is_flagged
            FROM sessions s
            JOIN users u ON s.user_id = u.user_id
            ORDER BY s.login_time DESC
        """)
    return jsonify([dict(r) for r in rows])


# GET /api/sessions/flagged?org_id=1
@sessions_bp.route("/flagged", methods=["GET"])
def get_flagged():
    org_id = request.args.get("org_id")
    if org_id:
        rows = query("""
            SELECT s.session_id, u.username, s.ip_address, s.device_info,
                   s.login_time, s.sta_tus
            FROM sessions s
            JOIN users u ON s.user_id = u.user_id
            WHERE s.is_flagged = TRUE AND s.org_id = %s
        """, (org_id,))
    else:
        rows = query("""
            SELECT s.session_id, u.username, s.ip_address, s.device_info,
                   s.login_time, s.sta_tus
            FROM sessions s
            JOIN users u ON s.user_id = u.user_id
            WHERE s.is_flagged = TRUE
        """)
    return jsonify([dict(r) for r in rows])


# ── TASK 1: POST /api/sessions/heartbeat ─────────────────────────────────────
# Updates last_active for the current session cookie every 2 minutes.
# Called silently by the JS setInterval in sessions.html.
@sessions_bp.route("/heartbeat", methods=["POST"])
def heartbeat():
    token = request.cookies.get("session_token")
    if token:
        query(
            "UPDATE sessions SET last_active = NOW() "
            "WHERE session_token = %s AND sta_tus = 'Active'",
            (token,),
        )
    return jsonify({"status": "ok"})
