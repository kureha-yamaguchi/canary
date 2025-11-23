"""Supabase database connection for Red Team Agent using REST API"""
import os
from dotenv import load_dotenv
from typing import Optional, List, Dict, Any
from pathlib import Path

# Load environment variables
load_dotenv()

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

def insert_red_team_run(run_id: str, model: str, url: str, success: bool = True) -> Optional[dict]:
    """Insert a red team agent run into the database"""
    if not is_connected():
        return None
    
    try:
        # Use upsert (insert or update on conflict)
        result = supabase_client.table("red_team_agent_runs").upsert({
            "run_id": run_id,
            "model": model,
            "url": url,
            "success": success
        }, on_conflict="run_id").execute()
        
        if result.data and len(result.data) > 0:
            return result.data[0]
        return None
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
    
    try:
        result = supabase_client.table("auditor_runs").insert({
            "run_id": run_id,
            "expected_vulnerability": expected_vulnerability,
            "auditor_judgement": auditor_judgement
        }).execute()
        
        if result.data and len(result.data) > 0:
            return result.data[0]
        return None
    except Exception as e:
        print(f"Error inserting auditor run: {e}")
        return None

def insert_ttp_run(run_id: str, ttp_found: str, mapping_type: str = None, mapping_rationale: str = None) -> Optional[dict]:
    """Insert a TTP master run result into the database"""
    if not is_connected():
        return None
    
    data = {
        "run_id": run_id,
        "ttp_found": ttp_found
    }
    
    if mapping_type:
        data["mapping_type"] = mapping_type
    if mapping_rationale:
        data["mapping_rationale"] = mapping_rationale
    
    try:
        result = supabase_client.table("ttp_master_runs").insert(data).execute()
        
        if result.data and len(result.data) > 0:
            return result.data[0]
        return None
    except Exception as e:
        print(f"Error inserting TTP run: {e}")
        return None

def insert_ttp_runs(run_id: str, ttps: List[str], mapping_type: str = None, mapping_rationale: str = None) -> List[dict]:
    """Insert multiple TTP runs for a single run_id with same mapping_type and rationale"""
    if not is_connected():
        return []
    
    if not ttps:
        return []
    
    # Prepare data for bulk insert
    data_list = []
    for ttp in ttps:
        item = {
            "run_id": run_id,
            "ttp_found": ttp
        }
        if mapping_type:
            item["mapping_type"] = mapping_type
        if mapping_rationale:
            item["mapping_rationale"] = mapping_rationale
        data_list.append(item)
    
    try:
        result = supabase_client.table("ttp_master_runs").insert(data_list).execute()
        
        if result.data:
            return result.data
        return []
    except Exception as e:
        print(f"Error inserting TTP runs: {e}")
        return []

def insert_ttp_runs_with_details(run_id: str, ttp_mappings: List[Dict[str, Any]]) -> List[dict]:
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
    
    if not ttp_mappings:
        return []
    
    # Prepare data for bulk insert
    data_list = []
    for mapping in ttp_mappings:
        ttp_id = mapping.get("ttp_id")
        if not ttp_id:
            continue
        
        item = {
            "run_id": run_id,
            "ttp_found": ttp_id
        }
        
        mapping_type = mapping.get("mapping_type")
        mapping_rationale = mapping.get("mapping_rationale")
        
        if mapping_type:
            item["mapping_type"] = mapping_type
        if mapping_rationale:
            item["mapping_rationale"] = mapping_rationale
        
        data_list.append(item)
    
    if not data_list:
        return []
    
    try:
        result = supabase_client.table("ttp_master_runs").insert(data_list).execute()
        
        if result.data:
            return result.data
        return []
    except Exception as e:
        print(f"Error inserting TTP runs with details: {e}")
        return []
