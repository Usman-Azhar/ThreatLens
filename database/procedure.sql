-- Resolves an alert and kills the related session.
-- Trace chain: alert → event → session, then close both ends.
-- p_analyst_id is unused for now, will hook into audit log later.
-- Usage: CALL resolve_alert(alert_id, analyst_user_id);

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
    -- find the event tied to this alert
    SELECT event_id INTO v_event_id
    FROM alerts
    WHERE alert_id = p_alert_id;

    -- then grab the session from that event
    SELECT session_id INTO v_session_id
    FROM events
    WHERE event_id = v_event_id;

    -- mark alert done
    UPDATE alerts
    SET status = 'Resolved'
    WHERE alert_id = p_alert_id;

    -- boot the session
    UPDATE sessions
    SET status = 'Terminated'
    WHERE session_id = v_session_id;

END;
$$;