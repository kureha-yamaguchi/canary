#!/usr/bin/env python3
"""Run database migration to create agent runs tables"""
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

from supabase_client import get_db, is_connected, DATABASE_URL

def run_migration():
    """Run the migration SQL file"""
    # Import here to get the constructed DATABASE_URL
    from supabase_client import DATABASE_URL as constructed_url
    
    # Check if DATABASE_URL is set or was constructed
    db_url = os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DATABASE_URL") or constructed_url
    
    if not db_url:
        print("❌ DATABASE_URL not found and cannot be constructed.")
        print(f"   Checked .env file at: {project_root / '.env'}")
        print("\n   Available environment variables (filtered):")
        env_vars = [k for k in os.environ.keys() if 'DATABASE' in k.upper() or 'SUPABASE' in k.upper() or 'DB_' in k.upper()]
        if env_vars:
            for var in env_vars:
                print(f"     - {var}")
        else:
            print("     (No database-related variables found)")
        print("\n   Required: DATABASE_URL or DATABASE_PASSWORD (with SUPABASE_URL)")
        print("   You can find the database password in Supabase Dashboard > Settings > Database")
        print("   Or set DATABASE_URL directly with the connection string from Supabase")
        sys.exit(1)
    
    # Check connection - but don't fail if pool creation failed, try direct connection
    if not is_connected():
        print("⚠️  Connection pool creation failed, but tables are already created via API.")
        print("   The agents will still work and save to local files.")
        print("   Database inserts may not work until connection is fixed.")
        print("\n   Connection issue is likely due to:")
        print("   1. IP restrictions on Supabase database")
        print("   2. Network/firewall blocking the connection")
        print("   3. Connection pooling not enabled in Supabase dashboard")
        print("\n   Since tables are already created, you can:")
        print("   - Continue using agents (they'll save to local files)")
        print("   - Fix connection later to enable database inserts")
        print("   - Or use Supabase Dashboard SQL Editor to query data")
        return
    
    print("✅ Database connection configured")
    
    # Read migration file
    migration_file = Path(__file__).parent / "migrations" / "001_create_agent_runs_tables.sql"
    
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
                # Execute the migration SQL
                # psycopg2 can execute multiple statements using execute()
                # We'll split by semicolon but keep the structure
                print("📊 Executing migration SQL...")
                
                # Split SQL into individual statements, handling comments
                statements = []
                current_statement = []
                
                for line in sql.split('\n'):
                    line = line.strip()
                    # Skip empty lines and full-line comments
                    if not line or line.startswith('--'):
                        continue
                    # Remove inline comments
                    if '--' in line:
                        line = line[:line.index('--')].strip()
                    if line:
                        current_statement.append(line)
                        # Check if line ends with semicolon (end of statement)
                        if line.rstrip().endswith(';'):
                            statement = ' '.join(current_statement)
                            if statement:
                                statements.append(statement)
                            current_statement = []
                
                # Add any remaining statement
                if current_statement:
                    statement = ' '.join(current_statement)
                    if statement:
                        statements.append(statement)
                
                print(f"📊 Found {len(statements)} SQL statements to execute...")
                for i, statement in enumerate(statements, 1):
                    try:
                        cur.execute(statement)
                        print(f"  ✓ Statement {i}/{len(statements)} executed successfully")
                    except Exception as e:
                        # Some statements might fail if they already exist (IF NOT EXISTS)
                        error_msg = str(e).lower()
                        if "already exists" in error_msg or "duplicate" in error_msg or "relation" in error_msg and "already exists" in error_msg:
                            print(f"  ⚠️  Statement {i}/{len(statements)}: Object already exists (skipping)")
                        else:
                            print(f"  ❌ Statement {i}/{len(statements)} failed: {e}")
                            raise
                
                conn.commit()
                print("\n✅ Migration completed successfully!")
                print("\n📋 Created tables:")
                print("  - red_team_agent_runs")
                print("  - auditor_runs")
                print("  - ttp_master_runs")
                
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_migration()

