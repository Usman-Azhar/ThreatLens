-- =============================================================
-- views.sql
-- ThreatLens — All Views
-- =============================================================


-- ── VIEW 1: vw_alert_summary ──────────────────────────────────
-- All alerts joined with their event and user info.
-- Used for quick alert investigation without manual joins.

CREATE OR REPLACE VIEW vw_alert_summary AS
SELECT
    a.alert_id,
    a.alert_type,
    a.severity,
    a.sta_tus,
    a.created_at,
    u.username,
    e.event_type,
    e.ip_address,
    e.times_tamp
FROM alerts a
JOIN events e ON a.event_id = e.event_id
JOIN users  u ON e.user_id  = u.user_id;


-- ── VIEW 2: vw_active_threats ─────────────────────────────────
-- All sessions where the session IP matches a known threat.
-- Directly shows which active sessions are from malicious IPs.

CREATE OR REPLACE VIEW vw_active_threats AS
SELECT
    s.session_id,
    u.username,
    s.ip_address,
    s.sta_tus,
    s.is_flagged,
    t.threat_type,
    t.last_updated
FROM sessions s
JOIN users u ON s.user_id = u.user_id
JOIN threat_intelligence t ON s.ip_address::text = t.value;


-- ── VIEW 3: vw_user_activity ──────────────────────────────────
-- Per-user event count summary grouped by event type.
-- Shows what each user has been doing and when they were last seen.

CREATE OR REPLACE VIEW vw_user_activity AS
SELECT
    u.username,
    e.event_type,
    COUNT(*)           AS total,
    MAX(e.times_tamp)  AS last_seen
FROM events e
JOIN users u ON e.user_id = u.user_id
GROUP BY u.username, e.event_type;


-- ── VIEW 4: vw_brute_force_summary ───────────────────────────
-- Users with 5+ failed logins within a 15-minute window.
-- Reusable version of the brute force query from queries.sql.

CREATE OR REPLACE VIEW vw_brute_force_summary AS
SELECT
    u.username,
    e.ip_address::text,
    COUNT(*)           AS failed_attempts,
    MIN(e.times_tamp)  AS first_attempt,
    MAX(e.times_tamp)  AS last_attempt
FROM events e
JOIN users u ON e.user_id = u.user_id
WHERE e.event_type = 'login_failed'
GROUP BY u.username, e.ip_address, DATE_TRUNC('hour', e.times_tamp)
HAVING COUNT(*) >= 5
   AND MAX(e.times_tamp) - MIN(e.times_tamp) <= INTERVAL '15 minutes';


-- ── VIEW 5: vw_role_access_matrix ────────────────────────────
-- Shows every role and its permissions from role_permissions.
-- Demonstrates 3NF: permissions are structured and queryable,
-- not a TEXT blob inside the roles table.

CREATE OR REPLACE VIEW vw_role_access_matrix AS
SELECT
    r.role_id,
    r.role_name,
    rp.permission,
    COUNT(*) OVER (PARTITION BY r.role_id) AS total_permissions
FROM roles r
JOIN role_permissions rp ON r.role_id = rp.role_id
ORDER BY r.role_id, rp.permission;