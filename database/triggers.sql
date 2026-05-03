-- =============================================================
-- triggers.sql
-- ThreatLens — All Triggers & Trigger Functions
-- =============================================================


-- ── TRIGGER 1: Brute Force Detection ─────────────────────────
-- Fires after every login_failed event insert.
-- If the same user has 6+ failed logins within 15 minutes,
-- automatically opens a brute_force alert.

CREATE OR REPLACE FUNCTION check_brute_force()
RETURNS TRIGGER AS $$
DECLARE
    fail_count INT;
BEGIN
    SELECT COUNT(*) INTO fail_count
    FROM events
    WHERE user_id    = NEW.user_id
      AND event_type = 'login_failed'
      AND times_tamp >= NOW() - INTERVAL '15 minutes';

    IF fail_count >= 6 THEN
        INSERT INTO alerts (event_id, alert_type, severity, sta_tus)
        VALUES (NEW.event_id, 'brute_force', 'High', 'Open');
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_brute_force
AFTER INSERT ON events
FOR EACH ROW
WHEN (NEW.event_type = 'login_failed')
EXECUTE FUNCTION check_brute_force();


-- ── TRIGGER 2: Flag Suspicious Session on Insert ─────────────
-- Fires before every session insert.
-- If the session IP exists in threat_intelligence,
-- automatically sets is_flagged = TRUE.

CREATE OR REPLACE FUNCTION flag_suspicious_session()
RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM threat_intelligence
        WHERE value = NEW.ip_address::text
    ) THEN
        NEW.is_flagged := TRUE;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_flag_suspicious_session
BEFORE INSERT ON sessions
FOR EACH ROW
EXECUTE FUNCTION flag_suspicious_session();


-- ── TRIGGER 3: Audit Log on Alert Status Change ───────────────
-- Fires after every alert UPDATE.
-- Only writes to audit_log when sta_tus actually changes.
-- No app code needed — PostgreSQL handles this automatically.

CREATE OR REPLACE FUNCTION log_alert_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.sta_tus IS DISTINCT FROM NEW.sta_tus THEN
        INSERT INTO audit_log (
            table_name, action, changed_by, changed_at, old_value, new_value
        )
        VALUES (
            'alerts',
            'UPDATE',
            'system',
            NOW(),
            'sta_tus: ' || OLD.sta_tus,
            'sta_tus: ' || NEW.sta_tus
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_audit_alert_status
AFTER UPDATE ON alerts
FOR EACH ROW
EXECUTE FUNCTION log_alert_status_change();


-- ── TRIGGER 4: Sync Login Attempts ───────────────────────────
-- Fires after every event insert.
-- If event_type is login_success or login_failed,
-- automatically copies the record into login_attempts.

CREATE OR REPLACE FUNCTION sync_login_attempt()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.event_type IN ('login_success', 'login_failed') THEN
        INSERT INTO login_attempts (
            user_id, ip_address, attempted_at, success, user_agent
        )
        VALUES (
            NEW.user_id,
            NEW.ip_address,
            NEW.times_tamp,
            NEW.success,
            NULL
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_sync_login_attempts
AFTER INSERT ON events
FOR EACH ROW
EXECUTE FUNCTION sync_login_attempt();