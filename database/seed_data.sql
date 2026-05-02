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
(1, 3, 'hassan.view', 'hassan@alliedbank.pk', '$2b$12$SFMfF9h0TASgJPs45.fIx.qJWZKvkr8ni1AEf4Gz2Mb1jY8EyZDwK', '2024-01-10 09:00:00'),
(1, 2, 'nadia.analyst', 'nadia@alliedbank.pk', '$2b$12$AHwUEGtPx8JmriRazkRpl.v7q.E5Ql9OzPVzn3E759fCtD5GV99lC', '2024-01-11 09:00:00'),
(1, 3, 'tariq.view', 'tariq@alliedbank.pk', '$2b$12$AkGz.a9FyV/cb/.PGP7i7.//009nxMipa6Xtdwc7rRJ6MIXZUHJJm', '2024-01-11 09:00:00'),
-- GIKI University users (org_id=2)
(2, 1, 'usman.admin', 'usman@giki.edu.pk', '$2b$12$x35wHtdJbbNWr6RUAkt..OcchiOH50XXEKzS3QvJFjCXOrdiuHamu', '2024-01-12 09:00:00'),
(2, 2, 'fatima.analyst', 'fatima@giki.edu.pk', '$2b$12$ZCTL6hqeoYqPP4hlS2KL5OGA/ZtAloOMsIhHZgWsjy8JeSg8roWV2', '2024-01-12 09:00:00'),
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