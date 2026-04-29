-- ── ABDULLAH TASK 7: 10 extra event rows for chart/demo variety ──────────────
-- Spread across different users and different days (Jan 19 – Jan 24)

INSERT INTO events (user_id, asset_id, session_id, times_tamp, event_type, ip_address, success, metadata) VALUES
-- login_success rows
(2,  1, 2, '2024-01-19 09:15:00', 'login_success',  '103.12.45.200', true,  'Normal login'),
(5,  1, 2, '2024-01-19 11:30:00', 'login_success',  '103.44.55.66',  true,  'Normal login'),
(7,  4, 4, '2024-01-20 08:45:00', 'login_success',  '10.0.0.7',      true,  'Normal login'),
(9,  4, 4, '2024-01-21 10:00:00', 'login_success',  '10.0.0.9',      true,  'Normal login'),
(10, 4, 4, '2024-01-22 09:00:00', 'login_success',  '10.0.0.10',     true,  'Normal login'),

-- login_failed rows (wrong passwords from different IPs)
(3,  1, 1, '2024-01-20 14:22:00', 'login_failed',   '88.99.100.11',  false, 'Wrong password'),
(8,  4, 4, '2024-01-21 03:45:00', 'login_failed',   '10.0.0.8',      false, 'Wrong password'),

-- file_download rows
(1,  3, 1, '2024-01-22 13:10:00', 'file_download',  '103.12.45.100', true,  'audit_log_jan.csv'),
(7,  6, 4, '2024-01-23 10:30:00', 'file_download',  '10.0.0.7',      true,  'grades_2024.xlsx'),

-- page_access row (normal user, non-admin page — no privilege alert)
(2,  1, 2, '2024-01-24 09:00:00', 'page_access',    '103.12.45.200', true,  'Accessed portal home');
