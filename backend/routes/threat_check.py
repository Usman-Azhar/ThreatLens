from db import query 

# check if IP is in threat list and flag it
def check_suspicious_ip(user_id, ip, session_id, event_id):
    results = query(
        "SELECT * FROM threat_intelligence WHERE value = %s",
        (ip,)
    )
    if results:
        query(
            "INSERT INTO alerts (event_id, alert_type, severity, sta_tus) VALUES (%s, 'suspicious_ip', 'Critical', 'Open')",
            (event_id,)
        )
        query(
            "UPDATE sessions SET is_flagged = TRUE, sta_tus = 'Suspicious' WHERE session_id = %s",
            (session_id,)
        )

# check if login time is between 2am and 5am
def check_off_hours(user_id, event_id, login_time):
    hour = login_time.hour
    if 2 <= hour < 5:
        query(
            "INSERT INTO alerts (event_id, alert_type, severity, sta_tus) VALUES (%s, 'off_hours_login', 'Medium', 'Open')",
            (event_id,)
        )

# check if user already has another active session on different IP
def check_concurrent_session(user_id, current_ip, event_id):
    results = query(
        "SELECT * FROM sessions WHERE user_id = %s AND sta_tus = 'Active' AND ip_address != %s",
        (user_id, current_ip)
    )
    if results:
        query(
            "INSERT INTO alerts (event_id, alert_type, severity, sta_tus) VALUES (%s, 'concurrent_session', 'High', 'Open')",
            (event_id,)
        )

# check if non admin is accessing admin panel
def check_privilege_escalation(user_id, asset_id, event_id, role_id):
    results = query(
        "SELECT asset_type FROM assets WHERE asset_id = %s",
        (asset_id,)
    )
    if results:
        asset_type = results[0]['asset_type']
        if asset_type == 'Admin_Panel' and role_id != 1:
            query(
                "INSERT INTO alerts (event_id, alert_type, severity, sta_tus) VALUES (%s, 'privilege_escalation', 'High', 'Open')",
                (event_id,)
            )

# mark unauthorized access and flag session
def check_unauthorized_access(user_id, session_id, event_id, route):
    query(
        """INSERT INTO alerts (event_id, alert_type, severity, sta_tus)
           VALUES (%s, 'privilege_escalation', 'High', 'Open')""",
        (event_id,)
    )
    query(
        """UPDATE sessions SET is_flagged = TRUE
           WHERE session_id = %s""",
        (session_id,)
    )