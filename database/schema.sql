-- SQL Tables File
-- all 8 CREATE TABLE statements 

-- Abdullah
Drop table if exists Organizations cascade;

Create table Organizations (
org_id Serial Primary Key,
org_name varchar(250),
created_at Timestamp
);


-- Fatima
Drop table if exists roles cascade;


CREATE TABLE roles (
    role_id    SERIAL PRIMARY KEY,
    role_name  VARCHAR(50)  NOT NULL,
    permissions TEXT
);

-- Fatima
Drop table if exists users cascade;


CREATE TABLE users (
    user_id       SERIAL PRIMARY KEY,
    org_id        INT          NOT NULL REFERENCES Organizations(org_id),
    role_id       INT          NOT NULL REFERENCES roles(role_id),
    username      VARCHAR(100) NOT NULL UNIQUE,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP    DEFAULT NOW()
);

-- Abdullah
Drop table if exists Assets cascade;

Create table Assets (
asset_id Serial Primary Key,
org_id Int references Organizations (org_id),
asset_name Varchar(255),
asset_type varchar(100)
);

-- Fatima
Drop table if exists sessions cascade;


CREATE TABLE sessions (
    session_id    SERIAL PRIMARY KEY,
    user_id       INT          NOT NULL REFERENCES users(user_id),
    org_id        INT          NOT NULL REFERENCES Organizations(org_id),
    session_token VARCHAR(256) NOT NULL UNIQUE,
    ip_address    INET,
    device_info   VARCHAR(255),
    login_time    TIMESTAMP    DEFAULT NOW(),
    last_active   TIMESTAMP    DEFAULT NOW(),
    logout_time   TIMESTAMP,
    sta_tus       VARCHAR(50)  DEFAULT 'Active' CHECK (sta_tus IN ('Active', 'Expired', 'Terminated', 'Suspicious')),
    is_flagged    BOOLEAN      DEFAULT FALSE
);

-- Usman 
Drop table if exists events cascade;


CREATE TABLE events (
    event_id    SERIAL PRIMARY KEY,
    user_id     INT          NOT NULL REFERENCES users(user_id),
    asset_id    INT          NOT NULL REFERENCES assets(asset_id),
    session_id  INT          NOT NULL REFERENCES sessions(session_id),
    times_tamp   TIMESTAMP    DEFAULT NOW(),
    event_type  VARCHAR(100) NOT NULL,
    ip_address  INET,
    success     BOOLEAN      DEFAULT FALSE,
    metadata    TEXT
);

-- Usman
Drop table if exists alerts cascade;


CREATE TABLE alerts (
    alert_id    SERIAL PRIMARY KEY,
    event_id    INT          NOT NULL REFERENCES events(event_id),
    alert_type  VARCHAR(100) NOT NULL,
    severity    VARCHAR(50)  CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    sta_tus      VARCHAR(50)  CHECK (sta_tus IN ('Open', 'Investigating', 'Resolved')),
    created_at  TIMESTAMP    DEFAULT NOW()
);

-- Abdullah
Drop table if exists Threat_Intelligence cascade;

Create table Threat_Intelligence (
threat_id Serial Primary Key,
threat_type Varchar(100),
value Varchar(255),
last_updated Timestamp
);




-- =============================================================
-- schema_fixes.sql
-- Run this ONCE in pgAdmin Query Tool
-- Fixes bugs + adds new tables for normalization demo
-- =============================================================


-- ── FIX 1: False Positive in alerts CHECK constraint ─────────
-- Your backend sends 'False Positive' but the CHECK only allowed
-- Open / Investigating / Resolved — this was silently crashing.
-- We drop the old constraint and add the corrected one.

ALTER TABLE alerts
    DROP CONSTRAINT IF EXISTS alerts_sta_tus_check;

ALTER TABLE alerts
    ADD CONSTRAINT alerts_sta_tus_check
    CHECK (sta_tus IN ('Open', 'Investigating', 'Resolved', 'False Positive'));


-- ── FIX 2: Make session_id nullable in events ─────────────────
-- auth.py inserts login_failed events before a session exists,
-- passing session_id = 1 as a placeholder right now.
-- Making it nullable is the correct schema design.

ALTER TABLE events
    ALTER COLUMN session_id DROP NOT NULL;


-- ── FIX 3: ON DELETE behaviour on foreign keys ────────────────
-- Your DROP TABLE statements use CASCADE but your FK definitions
-- had no ON DELETE rule — meaning deleting a parent row would
-- throw an error instead of cascading cleanly.

-- alerts → events: if an event is deleted, its alerts go too
ALTER TABLE alerts
    DROP CONSTRAINT IF EXISTS alerts_event_id_fkey;
ALTER TABLE alerts
    ADD CONSTRAINT alerts_event_id_fkey
    FOREIGN KEY (event_id) REFERENCES events(event_id)
    ON DELETE CASCADE;

-- events → sessions: if a session is deleted, its events stay
-- but the session_id is nulled out (forensic record preserved)
ALTER TABLE events
    DROP CONSTRAINT IF EXISTS events_session_id_fkey;
ALTER TABLE events
    ADD CONSTRAINT events_session_id_fkey
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    ON DELETE SET NULL;

-- events → assets: if an asset is removed, events keep the record
ALTER TABLE events
    DROP CONSTRAINT IF EXISTS events_asset_id_fkey;
ALTER TABLE events
    ADD CONSTRAINT events_asset_id_fkey
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
    ON DELETE SET NULL;


-- ── NEW TABLE 1: audit_log ────────────────────────────────────
-- Tracks every UPDATE made to the alerts table automatically.
-- Demonstrates: normalization, triggers, transaction awareness.
-- No app code needed — the trigger fires inside PostgreSQL.

CREATE TABLE IF NOT EXISTS audit_log (
    log_id      SERIAL PRIMARY KEY,
    table_name  VARCHAR(100) NOT NULL,
    action      VARCHAR(50)  NOT NULL,          -- 'UPDATE'
    changed_by  VARCHAR(100) DEFAULT 'system',  -- future: pass username
    changed_at  TIMESTAMP    DEFAULT NOW(),
    old_value   TEXT,                           -- old sta_tus
    new_value   TEXT                            -- new sta_tus
);


-- ── NEW TABLE 2: role_permissions ────────────────────────────
-- Normalizes permissions out of the roles.permissions TEXT column
-- into a proper junction table. Demonstrates 3NF — a role can
-- have many permissions, a permission can belong to many roles.

CREATE TABLE IF NOT EXISTS role_permissions (
    rp_id       SERIAL PRIMARY KEY,
    role_id     INT         NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission  VARCHAR(100) NOT NULL,
    UNIQUE (role_id, permission)
);

-- Seed with sensible defaults matching your existing roles
INSERT INTO role_permissions (role_id, permission)
VALUES
    (1, 'view_sessions'),
    (1, 'view_events'),
    (1, 'view_alerts'),
    (1, 'view_stats'),
    (1, 'flag_session'),
    (1, 'update_alert'),
    (2, 'view_sessions'),
    (2, 'view_events')
ON CONFLICT DO NOTHING;


-- ── NEW TABLE 3: login_attempts ──────────────────────────────
-- Dedicated table for login attempts, separate from events.
-- Cleaner schema design — events tracks what happened inside
-- the app, login_attempts tracks authentication specifically.
-- Demonstrates: proper normalization, separation of concerns.

CREATE TABLE IF NOT EXISTS login_attempts (
    attempt_id   SERIAL PRIMARY KEY,
    user_id      INT       REFERENCES users(user_id) ON DELETE SET NULL,
    ip_address   INET,
    attempted_at TIMESTAMP DEFAULT NOW(),
    success      BOOLEAN   NOT NULL,
    user_agent   VARCHAR(255)
);

