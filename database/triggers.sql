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