
-- schemas


-- DROP Tables
DROP TABLE IF EXISTS login_attempts    CASCADE;
DROP TABLE IF EXISTS role_permissions  CASCADE;
DROP TABLE IF EXISTS audit_log         CASCADE;
DROP TABLE IF EXISTS alerts            CASCADE;
DROP TABLE IF EXISTS events            CASCADE;
DROP TABLE IF EXISTS sessions          CASCADE;
DROP TABLE IF EXISTS assets            CASCADE;
DROP TABLE IF EXISTS users             CASCADE;
DROP TABLE IF EXISTS roles             CASCADE;
DROP TABLE IF EXISTS threat_intelligence CASCADE;
DROP TABLE IF EXISTS organizations     CASCADE;


-- Organizations
CREATE TABLE organizations (
    org_id     SERIAL      PRIMARY KEY,
    org_name   VARCHAR(250),
    created_at TIMESTAMP
);


-- Roles
CREATE TABLE roles (
    role_id     SERIAL       PRIMARY KEY,
    role_name   VARCHAR(50)  NOT NULL,
    permissions TEXT
);


-- Users
CREATE TABLE users (
    user_id       SERIAL       PRIMARY KEY,
    org_id        INT          NOT NULL REFERENCES organizations(org_id),
    role_id       INT          NOT NULL REFERENCES roles(role_id),
    username      VARCHAR(100) NOT NULL UNIQUE,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP    DEFAULT NOW(),
    is_active      BOOLEAN      DEFAULT TRUE
);


-- Assets
CREATE TABLE assets (
    asset_id   SERIAL       PRIMARY KEY,
    org_id     INT          REFERENCES organizations(org_id),
    asset_name VARCHAR(255),
    asset_type VARCHAR(100)
);


-- Sessions
CREATE TABLE sessions (
    session_id    SERIAL       PRIMARY KEY,
    user_id       INT          NOT NULL REFERENCES users(user_id),
    org_id        INT          NOT NULL REFERENCES organizations(org_id),
    session_token VARCHAR(256) NOT NULL UNIQUE,
    ip_address    INET,
    device_info   VARCHAR(255),
    login_time    TIMESTAMP    DEFAULT NOW(),
    last_active   TIMESTAMP    DEFAULT NOW(),
    logout_time   TIMESTAMP,
    sta_tus       VARCHAR(50)  DEFAULT 'Active'
                  CHECK (sta_tus IN ('Active', 'Expired', 'Terminated', 'Suspicious')),
    is_flagged    BOOLEAN      DEFAULT FALSE
);


-- Events
CREATE TABLE events (
    event_id   SERIAL       PRIMARY KEY,
    user_id    INT          NOT NULL REFERENCES users(user_id),
    asset_id   INT          REFERENCES assets(asset_id)   ON DELETE SET NULL,
    session_id INT          REFERENCES sessions(session_id) ON DELETE SET NULL,
    times_tamp TIMESTAMP    DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    ip_address INET,
    success    BOOLEAN      DEFAULT FALSE,
    metadata   TEXT
);


-- Alerts
CREATE TABLE alerts (
    alert_id   SERIAL       PRIMARY KEY,
    event_id   INT          NOT NULL REFERENCES events(event_id) ON DELETE CASCADE, 
    alert_type VARCHAR(100) NOT NULL,
    severity   VARCHAR(50)  CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    sta_tus    VARCHAR(50)  CHECK (sta_tus IN ('Open', 'Investigating', 'Resolved', 'False Positive')),
    created_at TIMESTAMP    DEFAULT NOW()
);


-- Threat Intelligence
CREATE TABLE threat_intelligence (
    threat_id    SERIAL       PRIMARY KEY,
    threat_type  VARCHAR(100),
    value        VARCHAR(255),
    last_updated TIMESTAMP
);


-- Audit Log
CREATE TABLE audit_log (
    log_id     SERIAL       PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    action     VARCHAR(50)  NOT NULL,
    changed_by VARCHAR(100) DEFAULT 'system',
    changed_at TIMESTAMP    DEFAULT NOW(),
    old_value  TEXT,
    new_value  TEXT
);


-- Role Permissions
-- Normalizes permissions out of roles.permissions TEXT column.
-- 3NF: a role has many permissions, a permission belongs to many roles.
CREATE TABLE role_permissions (
    rp_id      SERIAL       PRIMARY KEY,
    role_id    INT          NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission VARCHAR(100) NOT NULL,
    UNIQUE (role_id, permission)
);


-- Login Attempts
CREATE TABLE login_attempts (
    attempt_id   SERIAL    PRIMARY KEY,
    user_id      INT       REFERENCES users(user_id) ON DELETE SET NULL,
    ip_address   INET,
    attempted_at TIMESTAMP DEFAULT NOW(),
    success      BOOLEAN   NOT NULL,
    user_agent   VARCHAR(255)
);

ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE;
