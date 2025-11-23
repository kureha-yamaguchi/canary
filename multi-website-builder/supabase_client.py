"""Supabase database connection for Multi-Website Builder"""
import os
from dotenv import load_dotenv
from typing import Optional, Dict, Any
from pathlib import Path

# Load environment variables
project_root = Path(__file__).parent.parent
env_file = project_root / ".env"
if env_file.exists():
    load_dotenv(env_file)

def get_env(key: str) -> str | None:
    """Get environment variable, returning None if empty or not set"""
    value = os.getenv(key)
    return value.strip() if value and value.strip() else None

# Get Supabase credentials
SUPABASE_URL = get_env("SUPABASE_URL")
SUPABASE_SERVICE_KEY = get_env("SUPABASE_SERVICE_ROLE_KEY") or get_env("SUPABASE_SERVICE_KEY")

# Initialize Supabase client (optional - will be None if credentials not available)
supabase_client = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    try:
        from supabase import create_client, Client
        supabase_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    except ImportError:
        print("Warning: supabase-py library not installed. Install with: pip install supabase")
        supabase_client = None
    except Exception as e:
        print(f"Warning: Failed to create Supabase client: {e}")
        supabase_client = None
else:
    # Don't raise error - allow optional database connection
    supabase_client = None

def is_connected() -> bool:
    """Check if Supabase client is available"""
    return supabase_client is not None

def insert_builder_run(
    model: str,
    vulnerability_id: int,
    website_prompt_id: int,
    building_success: bool = False,
    supabase_connection_success: bool = False
) -> Optional[dict]:
    """Insert a multi-website builder run into the database"""
    if not is_connected():
        return None
    
    try:
        result = supabase_client.table("multi_website_builder_runs").insert({
            "model": model,
            "vulnerability_id": vulnerability_id,
            "website_prompt_id": website_prompt_id,
            "building_success": building_success,
            "supabase_connection_success": supabase_connection_success
        }).execute()
        
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error inserting builder run: {e}")
        return None

def test_connection() -> bool:
    """Test the Supabase connection by querying the table"""
    if not is_connected():
        return False
    
    try:
        # Try to query the table (will fail if table doesn't exist, which is fine)
        result = supabase_client.table("multi_website_builder_runs").select("id").limit(1).execute()
        return True
    except Exception as e:
        # Table might not exist yet, which is okay
        error_msg = str(e).lower()
        if "relation" in error_msg and "does not exist" in error_msg:
            return False  # Table doesn't exist - need to run migration
        return False  # Other error

