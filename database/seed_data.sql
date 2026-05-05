-- test data

TRUNCATE organizations RESTART IDENTITY CASCADE;

INSERT INTO organizations (org_name, created_at) VALUES
('Allied Bank', '2026-04-05 08:27:56'),
('GIKI University', '2026-05-07 08:01:33'),
('Khyber Teaching Hospital', '2026-05-01 10:07:55' );

TRUNCATE roles RESTART IDENTITY CASCADE;

INSERT INTO roles (role_name, permissions) VALUES
('Admin', 'Full access: view, manage users, resolve alerts, configure system'),
('Analyst', 'View events, investigate and update alert status'),
('Viewer', 'Read-only access to events and alerts');

TRUNCATE users RESTART IDENTITY CASCADE;

INSERT INTO users (org_id, role_id, username, email, password_hash, created_at) VALUES
(1, 1, 'ali', 'ali@alliedbank.pk', '$2b$12$Y.h7sz78hAehbt565xmba.gYFmOrVSfSSHhlYKWnneIDuMMeUHF2W', '2026-01-10 09:45:45'),
(1, 2, 'sara', 'sara@alliedbank.pk', '$2b$12$nzbH1fh5l1MExtcxnDTaEOdMu50AqdAa3hOEPldOfIWl8GSIjCIbW', '2026-02-10 11:39:56'),
(1, 3, 'hassan', 'hassan@alliedbank.pk', '$2b$12$ekHF5Bp9tPnwr3pKwI9wV.YjqZGOzrxglPfg03Fp61zyAhwhJD7GC', '2026-03-10 01:14:22'),

-- GIKI University users (org_id=2)
(2, 1, 'usman', 'usman@giki.edu.pk', '$2b$12$J4Wj4AASBDfqqew37F0/FOFh5d5hWQ/u7mLCSDovgviaFBj3uBRL2', '2025-09-12 13:14:12'),
(2, 2, 'fatima', 'fatima@giki.edu.pk', '$2b$12$a4gAN1YKWAgNRmv8UE99J.YBaxJDeXXV.3KsY5Tn1EHt9purJfJra', '2025-07-12 12:13:14'),
(2, 3, 'abdullah', 'abdullah@giki.edu.pk', '$2b$12$0Vj85..MH0lGteYBLLmj6ubIDxcgusof64uyJNYqxMM27I4JKsJ7C', '2026-11-12 23:24:00'),


--Khyber Teaching Hospital
(3, 1, 'dr.tariq', 'tariq_dr@kth.pk', '$2b$12$V1WNdk5u9RCjWPQFI0.XLuqpaS03hqVjM4jxPeLmbOFyB2YrQdR.q', '2025-08-12 11:11:11'),
(3, 2, 'dr.asrar', 'asrar_dr@kth.pk', '$2b$12$vs4apz8jK/A40XD2QiLrPeOjv5Znges67Uj02g2885dgzAJc7c0hu', '2026-05-12 23:23:23'),
(3, 3, 'dr.siraj', 'siraj_dr@kth.pk', '$2b$12$dq2wnKt1KKR8O8stdSearO1WasqcEWzUlJUZfXaybSw9eSPk9GZ1y', '2025-04-02 11:23:11');


TRUNCATE assets RESTART IDENTITY CASCADE;

INSERT INTO assets (org_id, asset_name, asset_type) VALUES
(1, 'Bank Login Portal', 'Web Application'),
(1, 'Bank Admin Panel', 'Admin_Panel'),
(1, 'Bank File Server', 'Database'),
(2, 'GIKI Student Portal', 'Web Application'),
(2, 'GIKI Admin Panel', 'Admin_Panel'),
(2, 'GIKI Database Server', 'Database'),
(3, 'KTH Patient Portal', 'Web Application'),
(3, 'KTH Admin Panel', 'Admin_Panel'),
(3, 'KTH Records Server', 'Database');


TRUNCATE threat_intelligence RESTART IDENTITY CASCADE;

INSERT INTO threat_intelligence (threat_type, value, last_updated) VALUES
('malicious_ip', '10.1.59.204', '2026-05-04'),
('malicious_ip', '45.33.32.156', '2025-11-17'),
('tor_exit_node', '185.220.101.45', '2025-03-08'),
('tor_exit_node', '185.220.101.46', '2024-07-22'),
('known_attacker','89.234.157.254', '2025-08-31'),
('known_attacker','94.102.49.190', '2024-11-05'),
('malicious_ip', '198.96.155.3', '2026-02-14'),
('tor_exit_node', '171.25.193.20', '2025-06-19'),
('known_attacker','107.189.10.143', '2024-09-27');