import psycopg2
from psycopg2.extras import RealDictCursor

DB_CONFIG = {
    "dbname":   "ThreatLens",
    "user":     "postgres",
    "password": "pgadmin",
    "host":     "localhost",
    "port":     "5432"
}

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def query(sql, params=None):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            if sql.strip().upper().startswith("SELECT"):
                return cur.fetchall()
            if "RETURNING" in sql.upper():
                result = cur.fetchall()
                conn.commit()
                return result
            conn.commit()
            return []
    finally:
        conn.close()

def get_current_user(token):
    if not token:
        return None
    rows = query("""
        SELECT u.user_id, u.username, u.role_id, u.org_id,
               o.org_name, s.session_id
        FROM sessions s
        JOIN users u ON s.user_id = u.user_id
        JOIN organizations o ON u.org_id = o.org_id
        WHERE s.session_token = %s
          AND s.sta_tus = 'Active'
    """, (token,))
    return rows[0] if rows else None