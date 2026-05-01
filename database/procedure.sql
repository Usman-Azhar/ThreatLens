-- PROCEDURE
-- Resolves an alert and flags the related session as Suspicious
CREATE OR REPLACE PROCEDURE resolve_alert(
    p_alert_id   INT,
    p_analyst_id INT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_event_id   INT;
    v_session_id INT;
BEGIN
    -- Get the event linked to this alert
    SELECT event_id INTO v_event_id
    FROM alerts
    WHERE alert_id = p_alert_id;

    -- Get the session linked to that event
    SELECT session_id INTO v_session_id
    FROM events
    WHERE event_id = v_event_id;

    -- Update alert status to Resolved
    UPDATE alerts
    SET sta_tus = 'Resolved'
    WHERE alert_id = p_alert_id;

    -- Mark the session as Suspicious
    UPDATE sessions
    SET sta_tus = 'Suspicious'
    WHERE session_id = v_session_id;

END;
$$;



CALL resolve_alert(1, 1);