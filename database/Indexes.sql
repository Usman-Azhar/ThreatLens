-- INDEXES

CREATE INDEX idx_events_user_event   ON events(user_id, event_type);

CREATE INDEX idx_events_timestamp    ON events(times_tamp);

CREATE INDEX idx_sessions_user_status ON sessions(user_id, sta_tus);




-- =============================================================
-- indexes_new.sql  (append to your existing Indexes.sql)
-- Run ONCE in pgAdmin
-- =============================================================

-- Already have: idx_events_user_event, idx_events_timestamp,
--               idx_sessions_user_status

-- Speeds up JOIN in every alerts query (events → alerts)
CREATE INDEX IF NOT EXISTS idx_alerts_event_id
    ON alerts(event_id);

-- Speeds up the status dropdown filter + HAVING queries on alerts
CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alerts(sta_tus);

-- Speeds up login_failed filtering inside brute force view/trigger
CREATE INDEX IF NOT EXISTS idx_events_type_time
    ON events(event_type, times_tamp DESC);

-- Speeds up the flag + status combo used in at_risk_orgs view
CREATE INDEX IF NOT EXISTS idx_sessions_flagged_status
    ON sessions(is_flagged, sta_tus);

-- Speeds up role-based permission lookups
CREATE INDEX IF NOT EXISTS idx_role_permissions_role
    ON role_permissions(role_id);


