-- =============================================================
-- procedure.sql
-- ThreatLens — Stored Procedures
-- =============================================================


-- ── PROCEDURE: resolve_alert ──────────────────────────────────
-- Resolves an alert and terminates the related session.
-- Called manually by an analyst after investigating a threat.
--
-- Parameters:
--   p_alert_id   — the alert to resolve
--   p_analyst_id — the analyst performing the action (for future audit use)
--
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
    -- Get the event linked to this alert
    SELECT event_id INTO v_event_id
    FROM alerts
    WHERE alert_id = p_alert_id;

    -- Get the session linked to that event
    SELECT session_id INTO v_session_id
    FROM events
    WHERE event_id = v_event_id;

    -- Mark the alert as Resolved
    UPDATE alerts
    SET sta_tus = 'Resolved'
    WHERE alert_id = p_alert_id;

    -- Terminate the session — threat is handled, session is closed
    UPDATE sessions
    SET sta_tus = 'Terminated'
    WHERE session_id = v_session_id;

END;
$$;