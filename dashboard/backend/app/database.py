"""Database connection to Supabase using direct PostgreSQL connection"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool
from contextlib import contextmanager
from dotenv import load_dotenv
from typing import Optional

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
    db_user = get_env("DB_USER") or get_env("SUPABASE_DB_USER")
    db_password = get_env("DB_PASSWORD") or get_env("SUPABASE_DB_PASSWORD")
    
    # Try to extract from SUPABASE_URL if it's the project URL
    supabase_url = get_env("SUPABASE_URL")
    if supabase_url and db_user and db_password:
        # Extract project ref from URL: https://xxxxx.supabase.co
        import re
        match = re.search(r'https://([^.]+)\.supabase\.co', supabase_url)
        if match:
            project_ref = match.group(1)
            db_host = db_host or f"{project_ref}.supabase.co"
    
    if db_host and db_user and db_password:
        DATABASE_URL = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
    else:
        raise ValueError(
            "Database connection not configured. Please provide one of:\n"
            "1. DATABASE_URL (full PostgreSQL connection string)\n"
            "2. Or SUPABASE_DATABASE_URL\n"
            "3. Or DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD\n"
            "You can find this in Supabase Dashboard > Settings > Database > Connection string\n"
            "Use the 'Connection pooling' or 'Direct connection' string."
        )

# Create connection pool
try:
    pool = SimpleConnectionPool(1, 20, DATABASE_URL)
except Exception as e:
    raise ValueError(
        f"Failed to create database connection pool: {str(e)}. "
        "Please check your DATABASE_URL or database connection parameters."
    ) from e

@contextmanager
def get_db():
    """Get database connection from pool"""
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)

def query_db(query: str, params: Optional[tuple] = None):
    """Execute a SELECT query and return results as list of dicts"""
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            return cur.fetchall()

# For compatibility with existing code that uses supabase.table()
class SupabaseTableProxy:
    """Proxy object to mimic supabase.table() interface using direct PostgreSQL"""
    def __init__(self, table_name: str):
        self.table_name = table_name
    
    def select(self, columns: str = "*"):
        return SupabaseQueryBuilder(self.table_name, columns)
    
    def insert(self, data: dict):
        """Insert data into table"""
        columns = list(data.keys())
        placeholders = [f"${i+1}" for i in range(len(columns))]
        query = f"INSERT INTO {self.table_name} ({', '.join(columns)}) VALUES ({', '.join(placeholders)}) RETURNING *"
        with get_db() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, tuple(data.values()))
                result = cur.fetchone()
                conn.commit()
                return type('Response', (), {'data': result if result else []})()
    
    def update(self, data: dict):
        return SupabaseQueryBuilder(self.table_name, "*", update_data=data)
    
    def delete(self):
        return SupabaseQueryBuilder(self.table_name, "*", delete=True)

class SupabaseQueryBuilder:
    """Query builder to mimic Supabase query interface"""
    def __init__(self, table_name: str, columns: str = "*", update_data: Optional[dict] = None, delete: bool = False):
        self.table_name = table_name
        self.columns = columns
        self.update_data = update_data
        self.delete = delete
        self.conditions = []
        self.params = []
        self.param_counter = 1
        self.order_by = None
        self.limit_val = None
        self.offset_val = None
        self.range_val = None
    
    def eq(self, column: str, value):
        placeholder = f"${self.param_counter}"
        self.conditions.append(f"{column} = {placeholder}")
        self.params.append(value)
        self.param_counter += 1
        return self
    
    def is_null(self, column: str, null: bool = True):
        """Add IS NULL or IS NOT NULL condition"""
        if null:
            self.conditions.append(f"{column} IS NULL")
        else:
            self.conditions.append(f"{column} IS NOT NULL")
        return self
    
    def neq(self, column: str, value):
        """Not equal condition"""
        placeholder = f"${self.param_counter}"
        self.conditions.append(f"{column} != {placeholder}")
        self.params.append(value)
        self.param_counter += 1
        return self
    
    def gte(self, column: str, value):
        placeholder = f"${self.param_counter}"
        self.conditions.append(f"{column} >= {placeholder}")
        self.params.append(value)
        self.param_counter += 1
        return self
    
    def lte(self, column: str, value):
        placeholder = f"${self.param_counter}"
        self.conditions.append(f"{column} <= {placeholder}")
        self.params.append(value)
        self.param_counter += 1
        return self
    
    def order(self, column: str, desc: bool = False):
        self.order_by = f"{column} {'DESC' if desc else 'ASC'}"
        return self
    
    def limit(self, count: int):
        self.limit_val = count
        return self
    
    def offset(self, count: int):
        self.offset_val = count
        return self
    
    def range(self, start: int, end: int):
        self.offset_val = start
        self.limit_val = end - start + 1
        return self
    
    def execute(self):
        """Execute the query"""
        where_clause = f" WHERE {' AND '.join(self.conditions)}" if self.conditions else ""
        order_clause = f" ORDER BY {self.order_by}" if self.order_by else ""
        limit_clause = f" LIMIT {self.limit_val}" if self.limit_val else ""
        offset_clause = f" OFFSET {self.offset_val}" if self.offset_val else ""
        
        # Build query and collect all parameters
        all_params = list(self.params)
        
        if self.delete:
            query = f"DELETE FROM {self.table_name}{where_clause} RETURNING *"
        elif self.update_data:
            # Add update params after where clause params
            update_params_start = len(self.params) + 1
            set_clause = ", ".join([f"{k} = ${update_params_start + i}" for i, k in enumerate(self.update_data.keys())])
            all_params.extend(list(self.update_data.values()))
            query = f"UPDATE {self.table_name} SET {set_clause}{where_clause} RETURNING *"
        else:
            query = f"SELECT {self.columns} FROM {self.table_name}{where_clause}{order_clause}{limit_clause}{offset_clause}"
        
        with get_db() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Must pass params if query has placeholders ($1, $2, etc.)
                has_placeholders = "$" in query
                if has_placeholders and all_params:
                    cur.execute(query, tuple(all_params))
                elif has_placeholders and not all_params:
                    # Query has placeholders but no params - this is an error
                    error_msg = f"Query has placeholders but no params provided. Query: {query[:150]}... Conditions: {self.conditions}"
                    print(f"ERROR: {error_msg}")
                    raise ValueError(error_msg)
                else:
                    # No placeholders, safe to execute without params
                    cur.execute(query)
                
                if self.delete or self.update_data:
                    conn.commit()
                    result = cur.fetchall()
                else:
                    result = cur.fetchall()
        
        # Convert RealDictRow to regular dict
        data = [dict(row) for row in result]
        return type('Response', (), {'data': data})()

# Create a supabase-like client interface
class SupabaseClient:
    def table(self, table_name: str):
        return SupabaseTableProxy(table_name)

supabase = SupabaseClient()

