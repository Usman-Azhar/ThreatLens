-- This trigger function checks if a user is trying to log in too many times and failing, runs after a failed login is recorded in the events table
-- If there are 6 or more failed attempts within the last 15 minutes, it creates an alert

CREATE OR REPLACE FUNCTION check_brute_force()
RETURNS TRIGGER AS $$
DECLARE
    fail_count INT;
BEGIN
    -- Count how many failed login attempts this user has in the last 15 minutes
    SELECT COUNT(*) INTO fail_count
    FROM events
    WHERE user_id    = NEW.user_id
      AND event_type = 'login_failed'
      AND times_tamp >= NOW() - INTERVAL '15 minutes';

    -- If failed attempts are 6 or more, insert a brute force alert
    IF fail_count >= 6 THEN
        INSERT INTO alerts (event_id, alert_type, severity, sta_tus)
        VALUES (NEW.event_id, 'brute_force', 'High', 'Open');
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- This trigger runs the brute force check automatically after a failed login event is inserted
CREATE OR REPLACE TRIGGER trg_brute_force
AFTER INSERT ON events
FOR EACH ROW
WHEN (NEW.event_type = 'login_failed')
EXECUTE FUNCTION check_brute_force();


-- This trigger checks if a session is suspicious based on its IP address
-- It runs before a new session is inserted into the sessions table and if P exists in threat_intelligence, the session is flagged

CREATE OR REPLACE FUNCTION flag_suspicious_session()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if the IP address exists in the threat intelligence table
    IF EXISTS (
        SELECT 1 FROM threat_intelligence
        WHERE value = NEW.ip_address::text
    ) THEN
        -- Mark the session as flagged if a match is found
        NEW.is_flagged := TRUE;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- This trigger runs before inserting a session to flag suspicious IPs
CREATE OR REPLACE TRIGGER trg_flag_suspicious_session
BEFORE INSERT ON sessions
FOR EACH ROW
EXECUTE FUNCTION flag_suspicious_session();


-- This trigger logs any change in alert status, runs after an alert is updated

CREATE OR REPLACE FUNCTION log_alert_status_change()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if the status has changed compared to the old value
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

-- This trigger automatically logs changes to alert status
CREATE OR REPLACE TRIGGER trg_audit_alert_status
AFTER UPDATE ON alerts
FOR EACH ROW
EXECUTE FUNCTION log_alert_status_change();


-- This trigger function copies login-related events into the login_attempts table, runs after a new event is inserted
-- works only for login_success and login_failed events

CREATE OR REPLACE FUNCTION sync_login_attempt()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if the event is related to login
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

-- This trigger keeps the login_attempts table updated automatically
CREATE OR REPLACE TRIGGER trg_sync_login_attempts
AFTER INSERT ON events
FOR EACH ROW
EXECUTE FUNCTION sync_login_attempt();