-- Indexes for the most queried columns across all tables.

-- EVENTS
CREATE INDEX IF NOT EXISTS idx_events_user_event
    ON events(user_id, event_type);

CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON events(timestamp);

-- DESC because brute force detection always wants latest failures first
CREATE INDEX IF NOT EXISTS idx_events_type_time
    ON events(event_type, timestamp DESC);


-- SESSIONS
CREATE INDEX IF NOT EXISTS idx_sessions_user_status
    ON sessions(user_id, status);

CREATE INDEX IF NOT EXISTS idx_sessions_flagged_status
    ON sessions(is_flagged, status);


-- ALERTS
CREATE INDEX IF NOT EXISTS idx_alerts_event_id
    ON alerts(event_id);

CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alerts(status);


-- ROLE PERMISSIONS
CREATE INDEX IF NOT EXISTS idx_role_permissions_role
    ON role_permissions(role_id);