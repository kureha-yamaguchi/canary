#!/usr/bin/env python3
"""Run database migration to create multi-website builder runs table"""
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root (parent of multi-website-builder)
project_root = Path(__file__).parent.parent
env_file = project_root / ".env"
if env_file.exists():
    load_dotenv(env_file)
    print(f"📄 Loaded .env from: {env_file}")
else:
    # Also try loading from current directory
    load_dotenv()
    print("📄 Attempting to load .env from current directory")

# Try to use Supabase REST API first, fall back to direct PostgreSQL connection
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")

def run_migration_supabase():
    """Run migration using Supabase REST API"""
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        return False
    
    try:
        from supabase import create_client
        client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        
        # Read migration file
        migration_file = Path(__file__).parent / "migrations" / "001_create_multi_website_builder_runs_table.sql"
        if not migration_file.exists():
            print(f"❌ Migration file not found: {migration_file}")
            return False
        
        print(f"📄 Reading migration file: {migration_file}")
        with open(migration_file, 'r', encoding='utf-8') as f:
            sql = f.read()
        
        # Split SQL into individual statements
        statements = [s.strip() for s in sql.split(';') if s.strip() and not s.strip().startswith('--')]
        
        print(f"🔌 Connecting to Supabase...")
        print(f"📊 Found {len(statements)} SQL statements to execute...")
        
        # Execute via Supabase RPC or direct SQL
        for i, statement in enumerate(statements, 1):
            try:
                # Use Supabase's rpc to execute SQL
                result = client.rpc('exec_sql', {'query': statement}).execute()
                print(f"  ✓ Statement {i}/{len(statements)} executed successfully")
            except Exception as e:
                # Fall back to direct connection if RPC not available
                print(f"  ⚠️  RPC method failed, trying direct connection...")
                return False
        
        print("\n✅ Migration completed successfully!")
        print("\n📋 Created table:")
        print("  - multi_website_builder_runs")
        return True
        
    except ImportError:
        print("⚠️  supabase-py library not installed. Install with: pip install supabase")
        return False
    except Exception as e:
        print(f"⚠️  Supabase API migration failed: {e}")
        return False

def run_migration_postgres():
    """Run migration using direct PostgreSQL connection"""
    if not DATABASE_URL:
        return False
    
    try:
        import psycopg2
        from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
        
        # Read migration file
        migration_file = Path(__file__).parent / "migrations" / "001_create_multi_website_builder_runs_table.sql"
        if not migration_file.exists():
            print(f"❌ Migration file not found: {migration_file}")
            return False
        
        print(f"📄 Reading migration file: {migration_file}")
        with open(migration_file, 'r', encoding='utf-8') as f:
            sql = f.read()
        
        # Split SQL into individual statements
        statements = [s.strip() for s in sql.split(';') if s.strip() and not s.strip().startswith('--')]
        
        print("🔌 Connecting to PostgreSQL database...")
        conn = psycopg2.connect(DATABASE_URL)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        
        try:
            with conn.cursor() as cur:
                print(f"📊 Found {len(statements)} SQL statements to execute...")
                for i, statement in enumerate(statements, 1):
                    try:
                        cur.execute(statement)
                        print(f"  ✓ Statement {i}/{len(statements)} executed successfully")
                    except Exception as e:
                        # Some statements might fail if they already exist (IF NOT EXISTS)
                        error_msg = str(e).lower()
                        if "already exists" in error_msg or "duplicate" in error_msg:
                            print(f"  ⚠️  Statement {i}/{len(statements)}: Object already exists (skipping)")
                        else:
                            print(f"  ❌ Statement {i}/{len(statements)} failed: {e}")
                            raise
                
                print("\n✅ Migration completed successfully!")
                print("\n📋 Created table:")
                print("  - multi_website_builder_runs")
        finally:
            conn.close()
        
        return True
        
    except ImportError:
        print("⚠️  psycopg2 library not installed. Install with: pip install psycopg2-binary")
        return False
    except Exception as e:
        print(f"❌ PostgreSQL migration failed: {e}")
        return False

def run_migration():
    """Run the migration using available method"""
    # Try Supabase API first
    if run_migration_supabase():
        return
    
    # Fall back to direct PostgreSQL connection
    if run_migration_postgres():
        return
    
    # If both fail, provide instructions
    print("\n❌ Migration failed. Please ensure one of the following is configured:")
    print("\nOption 1: Supabase REST API")
    print("  Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env")
    print("\nOption 2: Direct PostgreSQL connection")
    print("  Set DATABASE_URL in .env")
    print("  Format: postgresql://postgres:[PASSWORD]@[PROJECT-REF].supabase.co:5432/postgres")
    print("\nYou can also run the migration manually:")
    print("  1. Go to Supabase Dashboard > SQL Editor")
    print(f"  2. Copy contents of: {Path(__file__).parent / 'migrations' / '001_create_multi_website_builder_runs_table.sql'}")
    print("  3. Paste and execute")
    sys.exit(1)

if __name__ == "__main__":
    run_migration()

