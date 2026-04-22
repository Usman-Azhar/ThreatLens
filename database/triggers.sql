-- Auto-insert alert when brute force is detected (6th failed login within 15 min)
CREATE OR REPLACE FUNCTION check_brute_force()
RETURNS TRIGGER AS $$
DECLARE
    fail_count INT;
BEGIN
    -- count failed logins from same user in last 15 minutes
    SELECT COUNT(*) INTO fail_count
    FROM events
    WHERE user_id    = NEW.user_id
      AND event_type = 'login_failed'
      AND times_tamp >= NOW() - INTERVAL '15 minutes';

    -- on 6th attempt, create alert
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