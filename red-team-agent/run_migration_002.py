#!/usr/bin/env python3
"""Run database migration 002 to add mapping_type and mapping_rationale columns"""
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root (parent of red-team-agent)
project_root = Path(__file__).parent.parent
env_file = project_root / ".env"
if env_file.exists():
    load_dotenv(env_file)
    print(f"📄 Loaded .env from: {env_file}")
else:
    # Also try loading from current directory
    load_dotenv()
    print("📄 Attempting to load .env from current directory")

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from supabase_client import get_db, is_connected

def run_migration():
    """Run the migration 002 SQL file"""
    if not is_connected():
        print("❌ Database connection not available")
        print("   Please check your DATABASE_URL or database connection settings")
        sys.exit(1)
    
    print("✅ Database connection configured")
    
    # Read migration file
    migration_file = Path(__file__).parent / "migrations" / "002_add_ttp_mapping_fields.sql"
    
    if not migration_file.exists():
        print(f"❌ Migration file not found: {migration_file}")
        sys.exit(1)
    
    print(f"📄 Reading migration file: {migration_file}")
    with open(migration_file, 'r', encoding='utf-8') as f:
        sql = f.read()
    
    print("🔌 Connecting to database...")
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                # Split SQL into individual statements
                statements = [s.strip() for s in sql.split(';') if s.strip() and not s.strip().startswith('--')]
                
                print(f"📊 Found {len(statements)} SQL statements to execute...")
                for i, statement in enumerate(statements, 1):
                    try:
                        cur.execute(statement)
                        print(f"  ✓ Statement {i}/{len(statements)} executed successfully")
                    except Exception as e:
                        # Some statements might fail if they already exist (IF NOT EXISTS)
                        error_msg = str(e).lower()
                        if "already exists" in error_msg or "duplicate" in error_msg or "column" in error_msg and "already exists" in error_msg:
                            print(f"  ⚠️  Statement {i}/{len(statements)}: Object already exists (skipping)")
                        else:
                            print(f"  ❌ Statement {i}/{len(statements)} failed: {e}")
                            raise
                
                conn.commit()
                print("\n✅ Migration completed successfully!")
                print("\n📋 Added columns to ttp_master_runs:")
                print("  - mapping_type (VARCHAR(50))")
                print("  - mapping_rationale (TEXT)")
                print("  - Index on mapping_type")
                
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    run_migration()

