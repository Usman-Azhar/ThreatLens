-- Auto-insert alert when brute force is detected (6th failed login within 15 min)
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




-- Auto-flag session if login IP is in threat_intelligence
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






-- =============================================================
-- triggers_new.sql  (append to your existing triggers.sql)
-- Run ONCE in pgAdmin
-- =============================================================


-- ── TRIGGER: audit_log on alerts UPDATE ──────────────────────
-- Every time an alert's status is changed (Open → Investigating,
-- etc.), this trigger automatically writes a record to audit_log.
-- No Python change needed — PostgreSQL fires it automatically.
--
-- OLD = the row before the update
-- NEW = the row after the update
-- We only log when sta_tus actually changed (not every UPDATE).

CREATE OR REPLACE FUNCTION log_alert_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.sta_tus IS DISTINCT FROM NEW.sta_tus THEN
        INSERT INTO audit_log (
            table_name,
            action,
            changed_by,
            changed_at,
            old_value,
            new_value
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


-- ── TRIGGER: auto-populate login_attempts on event INSERT ────
-- Whenever a login_success or login_failed event is inserted,
-- this trigger copies the relevant fields into login_attempts.
-- Keeps login_attempts in sync automatically — zero Python change.

CREATE OR REPLACE FUNCTION sync_login_attempt()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.event_type IN ('login_success', 'login_failed') THEN
        INSERT INTO login_attempts (
            user_id,
            ip_address,
            attempted_at,
            success,
            user_agent
        )
        VALUES (
            NEW.user_id,
            NEW.ip_address,
            NEW.times_tamp,
            NEW.success,
            NULL   -- user_agent not stored in events; extend later if needed
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE TRIGGER trg_sync_login_attempts
AFTER INSERT ON events
FOR EACH ROW
EXECUTE FUNCTION sync_login_attempt();
