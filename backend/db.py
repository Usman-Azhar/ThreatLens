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
            conn.commit()
            return []
    finally:
        conn.close()