-- 1. BRUTE FORCE: users with 5+ failed logins within 15 minutes
SELECT u.username, e.ip_address, COUNT(*) AS failed_attempts,
       MIN(e.times_tamp) AS first_attempt, MAX(e.times_tamp) AS last_attempt
FROM events e
JOIN users u ON e.user_id = u.user_id
WHERE e.event_type = 'login_failed'
GROUP BY u.username, e.ip_address, DATE_TRUNC('hour', e.times_tamp)
HAVING COUNT(*) >= 5
   AND MAX(e.times_tamp) - MIN(e.times_tamp) <= INTERVAL '15 minutes';


-- 2. SUSPICIOUS IP: logins from known malicious IPs
SELECT u.username, e.ip_address, e.times_tamp,
       t.threat_type, e.event_type
FROM events e
JOIN users u ON e.user_id = u.user_id
JOIN threat_intelligence t ON e.ip_address::text = t.value
ORDER BY e.times_tamp DESC;


-- 3. OFF-HOURS LOGIN: logins between 2am and 5am
SELECT u.username, e.ip_address, e.times_tamp, e.event_type
FROM events e
JOIN users u ON e.user_id = u.user_id
WHERE EXTRACT(HOUR FROM e.times_tamp) >= 2
  AND EXTRACT(HOUR FROM e.times_tamp) <  5
ORDER BY e.times_tamp DESC;


-- 4. PRIVILEGE ESCALATION: non-admin users accessing admin panels
SELECT u.username, r.role_name, a.asset_name,
       a.asset_type, e.times_tamp, e.ip_address
FROM events e
JOIN users  u ON e.user_id  = u.user_id
JOIN roles  r ON u.role_id  = r.role_id
JOIN assets a ON e.asset_id = a.asset_id
WHERE a.asset_type = 'Admin_Panel'
  AND r.role_name  != 'Admin'
ORDER BY e.times_tamp DESC;


-- 5. CONCURRENT SESSIONS: same user active from 2+ different IPs
SELECT u.username, COUNT(*) AS active_sessions,
       ARRAY_AGG(s.ip_address::text) AS ip_addresses
FROM sessions s
JOIN users u ON s.user_id = u.user_id
WHERE s.sta_tus = 'Active'
GROUP BY u.username
HAVING COUNT(DISTINCT s.ip_address) > 1;