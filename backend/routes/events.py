from flask import Blueprint, request, jsonify
from db import query

events_bp = Blueprint("events", __name__)


# GET /api/events?org_id=1
@events_bp.route("/", methods=["GET"])
def get_events():
    org_id = request.args.get("org_id")
    if org_id:
        rows = query("""
            SELECT e.event_id, u.username, a.asset_name, e.event_type,
                   e.ip_address, e.success, e.times_tamp, e.metadata
            FROM events e
            JOIN users u    ON e.user_id  = u.user_id
            JOIN assets a   ON e.asset_id = a.asset_id
            WHERE u.org_id = %s
            ORDER BY e.times_tamp DESC
        """, (org_id,))
    else:
        rows = query("""
            SELECT e.event_id, u.username, a.asset_name, e.event_type,
                   e.ip_address, e.success, e.times_tamp, e.metadata
            FROM events e
            JOIN users u    ON e.user_id  = u.user_id
            JOIN assets a   ON e.asset_id = a.asset_id
            ORDER BY e.times_tamp DESC
        """)
    return jsonify([dict(r) for r in rows])


# GET /api/events/alerts?org_id=1
@events_bp.route("/alerts", methods=["GET"])
def get_alerts():
    org_id = request.args.get("org_id")
    if org_id:
        rows = query("""
            SELECT al.alert_id, al.alert_type, al.severity, al.sta_tus,
                   al.created_at, e.event_type, u.username, e.ip_address
            FROM alerts al
            JOIN events e ON al.event_id = e.event_id
            JOIN users u  ON e.user_id   = u.user_id
            WHERE u.org_id = %s
            ORDER BY al.created_at DESC
        """, (org_id,))
    else:
        rows = query("""
            SELECT al.alert_id, al.alert_type, al.severity, al.sta_tus,
                   al.created_at, e.event_type, u.username, e.ip_address
            FROM alerts al
            JOIN events e ON al.event_id = e.event_id
            JOIN users u  ON e.user_id   = u.user_id
            ORDER BY al.created_at DESC
        """)
    return jsonify([dict(r) for r in rows])


# PATCH /api/events/alerts/<id>
@events_bp.route("/alerts/<int:alert_id>", methods=["PATCH"])
def update_alert(alert_id):
    data = request.get_json()
    new_status = data.get("sta_tus")
    if new_status not in ("Open", "Investigating", "Resolved", "False Positive"):
        return jsonify({"error": "Invalid status"}), 400
    query("UPDATE alerts SET sta_tus = %s WHERE alert_id = %s", (new_status, alert_id))
    return jsonify({"message": "Alert updated"})


# GET /api/events/stats?org_id=1
@events_bp.route("/stats", methods=["GET"])
def get_stats():
    org_id = request.args.get("org_id")
    param = (org_id,) if org_id else None
    org_filter = "WHERE u.org_id = %s" if org_id else ""

    events_per_day = query(f"""
        SELECT DATE(e.times_tamp) as day, COUNT(*) as count
        FROM events e JOIN users u ON e.user_id = u.user_id
        {org_filter}
        GROUP BY day ORDER BY day
    """, param)

    severity_breakdown = query(f"""
        SELECT al.severity, COUNT(*) as count
        FROM alerts al
        JOIN events e ON al.event_id = e.event_id
        JOIN users u  ON e.user_id   = u.user_id
        {org_filter}
        GROUP BY al.severity
    """, param)

    alert_types = query(f"""
        SELECT al.alert_type, COUNT(*) as count
        FROM alerts al
        JOIN events e ON al.event_id = e.event_id
        JOIN users u  ON e.user_id   = u.user_id
        {org_filter}
        GROUP BY al.alert_type
    """, param)

    return jsonify({
        "events_per_day":     [dict(r) for r in events_per_day],
        "severity_breakdown": [dict(r) for r in severity_breakdown],
        "alert_types":        [dict(r) for r in alert_types],
    })


# POST /api/events/log
@events_bp.route("/log", methods=["POST"])
def log_event():
    data       = request.get_json()
    user_id    = data.get("user_id")
    asset_id   = data.get("asset_id")
    session_id = data.get("session_id")
    event_type = data.get("event_type")
    role_id    = data.get("role_id")
    success    = data.get("success", True)   # ← FIX: read from body, default True
    ip         = request.remote_addr

    row = query(
        """INSERT INTO events
               (user_id, asset_id, session_id, event_type, ip_address, success, times_tamp)
           VALUES (%s, %s, %s, %s, %s, %s, NOW())
           RETURNING event_id""",
        (user_id, asset_id, session_id, event_type, ip, success),
    )
    event_id = row[0]["event_id"]

    if event_type == "page_access" and role_id is not None:
        from routes.threat_check import check_privilege_escalation
        check_privilege_escalation(user_id, asset_id, event_id, role_id)

    return jsonify({"status": "logged", "event_id": event_id})