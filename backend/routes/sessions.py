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


# POST /api/sessions/heartbeat
@sessions_bp.route("/heartbeat", methods=["POST"])
def heartbeat():
    token = request.cookies.get("session_token")
    if token:
        rows = query(
            "SELECT sta_tus FROM sessions WHERE session_token = %s",
            (token,)
        )
        if not rows or rows[0]["sta_tus"] not in ("Active", "Suspicious"):
            return jsonify({"status": "terminated"}), 401
        query(
            "UPDATE sessions SET last_active = NOW() "
            "WHERE session_token = %s AND sta_tus = 'Active'",
            (token,),
        )
    return jsonify({"status": "ok"})


# POST /api/sessions/<session_id>/terminate
@sessions_bp.route("/<int:session_id>/terminate", methods=["POST"])
def terminate_session(session_id):
    token = request.cookies.get("session_token")
    from db import get_current_user
    user = get_current_user(token)

    if not user or user["role_id"] != 1:
        return jsonify({"error": "Unauthorized"}), 403

    # Find the alert linked to this session via the event chain
    rows = query("""
        SELECT a.alert_id
        FROM alerts a
        JOIN events e ON a.event_id = e.event_id
        WHERE e.session_id = %s
        LIMIT 1
    """, (session_id,))

    if rows:
        # Call the stored procedure (resolves alert + terminates session)
        alert_id = rows[0]["alert_id"]
        query("CALL resolve_alert(%s, %s)", (alert_id, user["user_id"]))
    else:
        # No linked alert — terminate session directly
        query(
            "UPDATE sessions SET sta_tus = 'Terminated' WHERE session_id = %s",
            (session_id,)
        )

    return jsonify({"status": "terminated"})