-- VIEWS

-- Summary of all open/investigating alerts with user and event info
CREATE OR REPLACE VIEW vw_alert_summary AS
SELECT a.alert_id, a.alert_type, a.severity, a.sta_tus, a.created_at,
       u.username, e.event_type, e.ip_address, e.times_tamp
FROM alerts a
JOIN events e ON a.event_id = e.event_id
JOIN users  u ON e.user_id  = u.user_id;


-- All sessions where IP matches a known threat
CREATE OR REPLACE VIEW vw_active_threats AS
SELECT s.session_id, u.username, s.ip_address,
       s.sta_tus, s.is_flagged, t.threat_type, t.last_updated
FROM sessions s
JOIN users u ON s.user_id = u.user_id
JOIN threat_intelligence t ON s.ip_address::text = t.value;


-- Per-user event count summary
CREATE OR REPLACE VIEW vw_user_activity AS
SELECT u.username, e.event_type,
       COUNT(*) AS total, MAX(e.times_tamp) AS last_seen
FROM events e
JOIN users u ON e.user_id = u.user_id
GROUP BY u.username, e.event_type;





-- =============================================================
-- views_new.sql  (append to your existing Views.sql)
-- Run ONCE in pgAdmin
-- =============================================================


-- ── VIEW 1: vw_brute_force_summary ───────────────────────────
-- Wraps the existing brute force query from queries.sql as a
-- permanent view. Same logic, now reusable without rewriting.
-- Python can query it with: SELECT * FROM vw_brute_force_summary

CREATE OR REPLACE VIEW vw_brute_force_summary AS
SELECT
    u.username,
    e.ip_address::text,
    COUNT(*)                      AS failed_attempts,
    MIN(e.times_tamp)             AS first_attempt,
    MAX(e.times_tamp)             AS last_attempt
FROM events e
JOIN users u ON e.user_id = u.user_id
WHERE e.event_type = 'login_failed'
GROUP BY u.username, e.ip_address, DATE_TRUNC('hour', e.times_tamp)
HAVING COUNT(*) >= 5
   AND MAX(e.times_tamp) - MIN(e.times_tamp) <= INTERVAL '15 minutes';


-- ── VIEW 2: vw_role_access_matrix ────────────────────────────
-- Shows which roles have which permissions by joining
-- roles → role_permissions. Directly demonstrates 3NF benefit:
-- permissions are no longer a TEXT blob in roles, they are
-- structured, queryable, and joinable.

CREATE OR REPLACE VIEW vw_role_access_matrix AS
SELECT
    r.role_id,
    r.role_name,
    rp.permission,
    COUNT(*) OVER (PARTITION BY r.role_id) AS total_permissions
FROM roles r
JOIN role_permissions rp ON r.role_id = rp.role_id
ORDER BY r.role_id, rp.permission;
