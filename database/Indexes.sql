-- =============================================================
-- indexes.sql
-- ThreatLens — All Indexes
-- =============================================================


-- ── EVENTS ────────────────────────────────────────────────────

-- Speeds up per-user event lookups and event type filtering
CREATE INDEX IF NOT EXISTS idx_events_user_event
    ON events(user_id, event_type);

-- Speeds up time-range queries on events
CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON events(times_tamp);

-- Speeds up login_failed filtering used in brute force detection
CREATE INDEX IF NOT EXISTS idx_events_type_time
    ON events(event_type, times_tamp DESC);


-- ── SESSIONS ──────────────────────────────────────────────────

-- Speeds up active session lookups per user
CREATE INDEX IF NOT EXISTS idx_sessions_user_status
    ON sessions(user_id, sta_tus);

-- Speeds up flagged + status combo used in threat views
CREATE INDEX IF NOT EXISTS idx_sessions_flagged_status
    ON sessions(is_flagged, sta_tus);


-- ── ALERTS ────────────────────────────────────────────────────

-- Speeds up JOIN from events to alerts
CREATE INDEX IF NOT EXISTS idx_alerts_event_id
    ON alerts(event_id);

-- Speeds up status filter on alerts table
CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alerts(sta_tus);


-- ── ROLE PERMISSIONS ──────────────────────────────────────────

-- Speeds up role-based permission lookups
CREATE INDEX IF NOT EXISTS idx_role_permissions_role
    ON role_permissions(role_id);