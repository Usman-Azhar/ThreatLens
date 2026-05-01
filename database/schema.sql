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