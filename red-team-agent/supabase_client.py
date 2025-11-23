"""Supabase database connection for Red Team Agent"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool
from contextlib import contextmanager
from dotenv import load_dotenv
from typing import Optional
from pathlib import Path

# Load environment variables
load_dotenv()

def get_env(key: str) -> str | None:
    """Get environment variable, returning None if empty or not set"""
    value = os.getenv(key)
    return value.strip() if value and value.strip() else None

# Try to get database connection string - this is the easiest way
DATABASE_URL = get_env("DATABASE_URL") or get_env("SUPABASE_DATABASE_URL")

# If no connection string, try to construct from components
if not DATABASE_URL:
    # Get connection components
    db_host = get_env("DB_HOST") or get_env("SUPABASE_DB_HOST")
    db_port = get_env("DB_PORT") or get_env("SUPABASE_DB_PORT") or "5432"
    db_name = get_env("DB_NAME") or get_env("SUPABASE_DB_NAME") or "postgres"
    db_user = get_env("DB_USER") or get_env("SUPABASE_DB_USER") or "postgres"
    db_password = get_env("DB_PASSWORD") or get_env("SUPABASE_DB_PASSWORD") or get_env("DATABASE_PASSWORD")
    
    # Try to extract from SUPABASE_URL if it's the project URL
    supabase_url = get_env("SUPABASE_URL")
    if supabase_url and db_password:
        # Extract project ref from URL: https://xxxxx.supabase.co
        import re
        match = re.search(r'https://([^.]+)\.supabase\.co', supabase_url)
        if match:
            project_ref = match.group(1)
            db_host = db_host or f"{project_ref}.supabase.co"
            # Use connection pooler port (6543) by default for better reliability
            if db_port == "5432":
                db_port = "6543"
    
    if db_host and db_user and db_password:
        # Add SSL mode for Supabase connections
        DATABASE_URL = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}?sslmode=require"
    else:
        # Don't raise error - allow optional database connection
        DATABASE_URL = None

# Create connection pool if DATABASE_URL is available
pool = None
if DATABASE_URL:
    try:
        pool = SimpleConnectionPool(1, 20, DATABASE_URL)
    except Exception as e:
        print(f"Warning: Failed to create database connection pool: {str(e)}")
        print("Database logging will be disabled. Set DATABASE_URL or database connection parameters to enable.")
        pool = None

@contextmanager
def get_db():
    """Get database connection from pool"""
    if not pool:
        raise ValueError("Database connection not configured. Set DATABASE_URL or database connection parameters.")
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)

def is_connected() -> bool:
    """Check if database connection is available"""
    return pool is not None

def insert_red_team_run(run_id: str, model: str, url: str, success: bool = True) -> Optional[dict]:
    """Insert a red team agent run into the database"""
    if not is_connected():
        return None
    
    query = """
        INSERT INTO red_team_agent_runs (run_id, model, url, success)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (run_id) DO UPDATE SET
            model = EXCLUDED.model,
            url = EXCLUDED.url,
            success = EXCLUDED.success
        RETURNING *
    """
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, (run_id, model, url, success))
                result = cur.fetchone()
                return dict(result) if result else None
    except Exception as e:
        print(f"Error inserting red team run: {e}")
        return None

def insert_auditor_run(run_id: str, expected_vulnerability: str, auditor_judgement: str) -> Optional[dict]:
    """Insert an auditor run result into the database"""
    if not is_connected():
        return None
    
    # Validate auditor_judgement
    if auditor_judgement not in ['success', 'failure']:
        raise ValueError(f"auditor_judgement must be 'success' or 'failure', got: {auditor_judgement}")
    
    query = """
        INSERT INTO auditor_runs (run_id, expected_vulnerability, auditor_judgement)
        VALUES (%s, %s, %s)
        RETURNING *
    """
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, (run_id, expected_vulnerability, auditor_judgement))
                result = cur.fetchone()
                return dict(result) if result else None
    except Exception as e:
        print(f"Error inserting auditor run: {e}")
        return None

def insert_ttp_run(run_id: str, ttp_found: str, mapping_type: str = None, mapping_rationale: str = None) -> Optional[dict]:
    """Insert a TTP master run result into the database"""
    if not is_connected():
        return None
    
    query = """
        INSERT INTO ttp_master_runs (run_id, ttp_found, mapping_type, mapping_rationale)
        VALUES (%s, %s, %s, %s)
        RETURNING *
    """
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, (run_id, ttp_found, mapping_type, mapping_rationale))
                result = cur.fetchone()
                return dict(result) if result else None
    except Exception as e:
        print(f"Error inserting TTP run: {e}")
        return None

def insert_ttp_runs(run_id: str, ttps: list[str], mapping_type: str = None, mapping_rationale: str = None) -> list[dict]:
    """Insert multiple TTP runs for a single run_id with same mapping_type and rationale"""
    if not is_connected():
        return []
    
    results = []
    for ttp in ttps:
        result = insert_ttp_run(run_id, ttp, mapping_type, mapping_rationale)
        if result:
            results.append(result)
    return results

def insert_ttp_runs_with_details(run_id: str, ttp_mappings: list[dict]) -> list[dict]:
    """
    Insert multiple TTP runs with individual mapping details
    
    Args:
        run_id: The run ID
        ttp_mappings: List of dicts with keys: ttp_id, mapping_type, mapping_rationale
    
    Returns:
        List of inserted records
    """
    if not is_connected():
        return []
    
    results = []
    for mapping in ttp_mappings:
        ttp_id = mapping.get("ttp_id")
        mapping_type = mapping.get("mapping_type")
        mapping_rationale = mapping.get("mapping_rationale")
        
        if ttp_id:
            result = insert_ttp_run(run_id, ttp_id, mapping_type, mapping_rationale)
            if result:
                results.append(result)
    return results

