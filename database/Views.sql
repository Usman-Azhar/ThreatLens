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