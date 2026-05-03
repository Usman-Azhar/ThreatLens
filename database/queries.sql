-- =============================================================
-- queries.sql
-- ThreatLens — Security Analysis Queries
-- Run these manually in pgAdmin to investigate threats
-- =============================================================


-- ── QUERY 1: Brute Force Detection ───────────────────────────
-- Users with 5+ failed logins within a 15-minute window.

SELECT
    u.username,
    e.ip_address,
    COUNT(*)           AS failed_attempts,
    MIN(e.times_tamp)  AS first_attempt,
    MAX(e.times_tamp)  AS last_attempt
FROM events e
JOIN users u ON e.user_id = u.user_id
WHERE e.event_type = 'login_failed'
GROUP BY u.username, e.ip_address, DATE_TRUNC('hour', e.times_tamp)
HAVING COUNT(*) >= 5
   AND MAX(e.times_tamp) - MIN(e.times_tamp) <= INTERVAL '15 minutes';


-- ── QUERY 2: Suspicious IP Logins ────────────────────────────
-- Events where the IP matches a known malicious entry
-- in threat_intelligence.

SELECT
    u.username,
    e.ip_address,
    e.times_tamp,
    t.threat_type,
    e.event_type
FROM events e
JOIN users u ON e.user_id = u.user_id
JOIN threat_intelligence t ON e.ip_address::text = t.value
ORDER BY e.times_tamp DESC;


-- ── QUERY 3: Off-Hours Logins ─────────────────────────────────
-- Logins that occurred between 2am and 5am.

SELECT
    u.username,
    e.ip_address,
    e.times_tamp,
    e.event_type
FROM events e
JOIN users u ON e.user_id = u.user_id
WHERE EXTRACT(HOUR FROM e.times_tamp) >= 2
  AND EXTRACT(HOUR FROM e.times_tamp) <  5
ORDER BY e.times_tamp DESC;


-- ── QUERY 4: Privilege Escalation ────────────────────────────
-- Non-admin users who accessed an Admin_Panel asset.

SELECT
    u.username,
    r.role_name,
    a.asset_name,
    a.asset_type,
    e.times_tamp,
    e.ip_address
FROM events e
JOIN users  u ON e.user_id  = u.user_id
JOIN roles  r ON u.role_id  = r.role_id
JOIN assets a ON e.asset_id = a.asset_id
WHERE a.asset_type = 'Admin_Panel'
  AND r.role_name  != 'Admin'
ORDER BY e.times_tamp DESC;


-- ── QUERY 5: Concurrent Sessions ─────────────────────────────
-- Users with active sessions from more than one IP address.

SELECT
    u.username,
    COUNT(*)                        AS active_sessions,
    ARRAY_AGG(s.ip_address::text)   AS ip_addresses
FROM sessions s
JOIN users u ON s.user_id = u.user_id
WHERE s.sta_tus = 'Active'
GROUP BY u.username
HAVING COUNT(DISTINCT s.ip_address) > 1;