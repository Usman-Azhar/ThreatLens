-- fake test data for all tables

INSERT INTO organizations (org_name, created_at) VALUES
('Allied Bank', '2024-01-01 08:00:00'),
('GIKI University', '2024-01-01 08:00:00');


INSERT INTO roles (role_name, permissions) VALUES
('Admin', 'Full access: view, manage users, resolve alerts, configure system'),
('Analyst', 'View events, investigate and update alert status'),
('Viewer', 'Read-only access to events and alerts');


INSERT INTO users (org_id, role_id, username, email, password_hash, created_at) VALUES
(1, 1, 'ali.admin', 'ali@alliedbank.pk', '$2b$12$xxgpdxf7hBxP3BbBltuCzO0MI82cvMtx7jTJ2AkxhcYK6l7.kkwn2', '2024-01-10 09:00:00'),
(1, 2, 'sara.analyst', 'sara@alliedbank.pk', '$2b$12$qJj7ohXgVMV1q0.MbG2pv.bqxoO7.fo2aDsXegM6V7B5dFTblvQVi', '2024-01-10 09:00:00'),
(1, 3, 'hassan.view', 'hassan@alliedbank.pk', '$2b$12$hashed_view_pass$2b$12$SFMfF9h0TASgJPs45.fIx.qJWZKvkr8ni1AEf4Gz2Mb1jY8EyZDwK', '2024-01-10 09:00:00'),
(1, 2, 'nadia.analyst', 'nadia@alliedbank.pk', '$2b$12$AHwUEGtPx8JmriRazkRpl.v7q.E5Ql9OzPVzn3E759fCtD5GV99lC', '2024-01-11 09:00:00'),
(1, 3, 'tariq.view', 'tariq@alliedbank.pk', '$2b$12$AkGz.a9FyV/cb/.PGP7i7.//009nxMipa6Xtdwc7rRJ6MIXZUHJJm', '2024-01-11 09:00:00'),
-- GIKI University users (org_id=2)
(2, 1, 'usman.admin', 'usman@giki.edu.pk', '$2b$12$x35wHtdJbbNWr6RUAkt..OcchiOH50XXEKzS3QvJFjCXOrdiuHamu', '2024-01-12 09:00:00'),
(2, 2, 'fatima.analyst', 'fatima@giki.edu.pk', '$$2b$12$ZCTL6hqeoYqPP4hlS2KL5OGA/ZtAloOMsIhHZgWsjy8JeSg8roWV2', '2024-01-12 09:00:00'),
(2, 3, 'abdullahg.view', 'abdullah@giki.edu.pk', '$2b$12$K8NhsHWZsOueRHPYUfEF1OcdLlrOTB2tY/w6tTYLkrARMetrtKjqi', '2024-01-12 09:00:00'),
(2, 2, 'bilal.analyst', 'bilal@giki.edu.pk', '$2b$12$Zutot6LaY25elC5MNiSqJutn.yh1V.TFXMEPEzK3DqB4Nzr8ZlUuq', '2024-01-13 09:00:00'),
(2, 3, 'zara.view', 'zara@giki.edu.pk', '$2b$12$SHSjmWQnTQl0.RdLq2qoLewVyok7QujVAN1wFN.glsoX1GBamiMRy', '2024-01-13 09:00:00');


INSERT INTO assets (org_id, asset_name, asset_type) VALUES
(1, 'Bank Login Portal', 'Web Application'),
(1, 'Bank Admin Panel', 'Admin_Panel'),
(1, 'Bank File Server', 'File Server'),
(2, 'GIKI Student Portal', 'Web Application'),
(2, 'GIKI Admin Panel', 'Admin_Panel'),
(2, 'GIKI Database Server', 'Database');


INSERT INTO threat_intelligence (threat_type, value, last_updated) VALUES
('malicious_ip', '45.33.32.156', '2024-01-01'),
('malicious_ip', '192.42.116.16', '2024-01-01'),
('tor_exit_node', '185.220.101.45', '2024-01-01'),
('tor_exit_node', '185.220.101.46', '2024-01-01'),
('known_attacker', '89.234.157.254', '2024-01-01'),
('known_attacker', '94.102.49.190', '2024-01-01'),
('malicious_ip', '198.96.155.3', '2024-01-02'),
('malicious_ip', '199.87.154.255', '2024-01-02'),
('tor_exit_node', '171.25.193.20', '2024-01-03'),
('known_attacker', '107.189.10.143', '2024-01-03');


INSERT INTO sessions (user_id, org_id, session_token, ip_address, device_info, login_time, last_active, logout_time, sta_tus, is_flagged) VALUES
(1, 1, 'tok_ali_001', '103.12.45.100', 'Chrome on Windows 11', '2024-01-15 09:00:00', '2024-01-15 09:45:00', '2024-01-15 10:00:00', 'Expired', false),
(3, 1, 'tok_hassan_001', '103.12.45.200', 'Firefox on Ubuntu', '2024-01-15 10:00:00', '2024-01-15 11:00:00', NULL, 'Active', false),
(3, 1, 'tok_hassan_002', '45.33.32.156', 'Chrome on Android', '2024-01-15 10:05:00', '2024-01-15 10:30:00', NULL, 'Active', true),
-- ^ hassan active from 2 IPs = concurrent session detection
(6, 2, 'tok_usman_001', '10.0.0.5', 'Chrome on Windows 11', '2024-01-15 08:00:00', '2024-01-15 11:00:00', NULL, 'Active', false);


-- Normal successful logins
INSERT INTO events (user_id, asset_id, session_id, times_tamp, event_type, ip_address, success, metadata) VALUES
(1, 1, 1, '2024-01-15 09:00:00', 'login_success', '103.12.45.100', true,  'Normal login'),
(2, 1, 2, '2024-01-15 10:00:00', 'login_success', '103.12.45.200', true,  'Normal login'),
(6, 4, 4, '2024-01-15 08:00:00', 'login_success', '10.0.0.5',      true,  'Normal login'),

-- BRUTE FORCE: user_id=4 fails 6 times within 15 minutes
(4, 1, 1, '2024-01-16 14:00:00', 'login_failed', '77.88.55.60', false, 'Wrong password'),
(4, 1, 1, '2024-01-16 14:02:00', 'login_failed', '77.88.55.60', false, 'Wrong password'),
(4, 1, 1, '2024-01-16 14:04:00', 'login_failed', '77.88.55.60', false, 'Wrong password'),
(4, 1, 1, '2024-01-16 14:06:00', 'login_failed', '77.88.55.60', false, 'Wrong password'),
(4, 1, 1, '2024-01-16 14:08:00', 'login_failed', '77.88.55.60', false, 'Wrong password'),
(4, 1, 1, '2024-01-16 14:10:00', 'login_failed', '77.88.55.60', false, 'Wrong password'),

-- SUSPICIOUS IP: login from threat_intelligence IP
(3, 1, 3, '2024-01-15 10:05:00', 'login_success', '45.33.32.156', true, 'Login from flagged IP'),

-- OFF-HOURS: login between 2am and 5am
(5, 1, 2, '2024-01-17 03:15:00', 'login_success', '103.44.55.66', true, 'Unusual hour login'),
(8, 4, 4, '2024-01-18 04:30:00', 'login_success', '10.0.0.9',     true, 'Unusual hour login'),

-- PRIVILEGE ESCALATION: non-admin accessing Admin_Panel (asset_id 2 or 5)
(3, 2, 2, '2024-01-15 11:00:00', 'page_access', '103.12.45.200', true, 'Accessed admin panel'),
(5, 2, 2, '2024-01-16 09:00:00', 'page_access', '103.44.55.66', true, 'Accessed admin panel'),
(8, 5, 4, '2024-01-17 10:00:00', 'page_access', '10.0.0.9',     true, 'Accessed admin panel'),

-- File downloads
(2, 3, 2, '2024-01-15 10:30:00', 'file_download', '103.12.45.200', true, 'report_q4_2023.pdf'),
(7, 6, 4, '2024-01-15 09:00:00', 'file_download', '10.0.0.7',     true, 'students_list.xlsx'),

-- Spread across days for the events-per-day chart
(1, 1, 1, '2024-01-14 10:00:00', 'login_success', '103.12.45.100', true, 'Normal'),
(2, 1, 2, '2024-01-14 11:00:00', 'login_success', '103.12.45.200', true, 'Normal'),
(4, 1, 1, '2024-01-13 09:30:00', 'login_failed',  '77.88.55.60',   false, 'Wrong password'),
(6, 4, 4, '2024-01-13 08:00:00', 'login_success', '10.0.0.5',      true, 'Normal'),
(7, 4, 4, '2024-01-12 14:00:00', 'login_success', '10.0.0.7',      true, 'Normal'),
(1, 3, 1, '2024-01-12 15:00:00', 'file_download', '103.12.45.100', true, 'data_export.csv'),
(9, 5, 4, '2024-01-11 10:00:00', 'login_success', '10.0.0.9',      true, 'Normal'),
(10, 4, 4, '2024-01-11 11:00:00', 'login_success', '10.0.0.10',     true, 'Normal');


INSERT INTO alerts (event_id, alert_type, severity, sta_tus, created_at) VALUES
(
    (SELECT event_id FROM events WHERE event_type = 'login_failed' LIMIT 1 OFFSET 5), 
    'brute_force', 'High', 'Open', '2024-01-16 14:10:01'
),
(
    (SELECT event_id FROM events WHERE metadata = 'Login from flagged IP' LIMIT 1), 
    'suspicious_ip', 'Critical', 'Investigating', '2024-01-15 10:05:01'
),
(
    (SELECT event_id FROM events WHERE metadata = 'Unusual hour login' LIMIT 1), 
    'off_hours_login', 'Medium', 'Open', '2024-01-17 03:15:01'
),
(
    (SELECT event_id FROM events WHERE metadata = 'Accessed admin panel' LIMIT 1), 
    'privilege_escalation', 'High', 'Open', '2024-01-15 11:00:01'
),
(
    (SELECT event_id FROM events WHERE metadata = 'Accessed admin panel' LIMIT 1 OFFSET 1), 
    'privilege_escalation', 'High', 'Resolved', '2024-01-16 09:00:01'
);