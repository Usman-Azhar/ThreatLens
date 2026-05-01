-- INDEXES

CREATE INDEX idx_events_user_event   ON events(user_id, event_type);

CREATE INDEX idx_events_timestamp    ON events(times_tamp);

CREATE INDEX idx_sessions_user_status ON sessions(user_id, sta_tus);