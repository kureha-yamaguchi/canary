# Database Setup Guide

This guide explains how to set up Supabase database connection for logging agent runs.

## Tables Created

The migration creates three tables:

1. **`red_team_agent_runs`**: Stores basic information about each agent run
   - `run_id`, `model`, `url`, `timestamp`, `success`

2. **`auditor_runs`**: Stores auditor analysis results
   - `run_id`, `timestamp`, `expected_vulnerability`, `auditor_judgement`

3. **`ttp_master_runs`**: Stores TTP (MITRE ATT&CK) findings
   - `run_id`, `timestamp`, `ttp_found` (multiple rows per run if multiple TTPs found)

## Database Connection Setup

### Option 1: Using DATABASE_URL (Recommended)

Set the `DATABASE_URL` environment variable with your Supabase PostgreSQL connection string:

```bash
export DATABASE_URL="postgresql://postgres:[YOUR-PASSWORD]@[PROJECT-REF].supabase.co:5432/postgres"
```

You can find this in Supabase Dashboard:
- Go to **Settings** > **Database**
- Copy the **Connection string** (use "Direct connection" or "Connection pooling")

### Option 2: Using Individual Components

Set these environment variables:

```bash
export SUPABASE_URL="https://[PROJECT-REF].supabase.co"
export DB_USER="postgres"
export DB_PASSWORD="[YOUR-PASSWORD]"
export DB_HOST="[PROJECT-REF].supabase.co"
export DB_PORT="5432"
export DB_NAME="postgres"
```

### Option 3: Using .env File

Create a `.env` file in the project root or `red-team-agent/` directory:

```env
DATABASE_URL=postgresql://postgres:[YOUR-PASSWORD]@[PROJECT-REF].supabase.co:5432/postgres
```

Or use individual components:

```env
SUPABASE_URL=https://[PROJECT-REF].supabase.co
DB_USER=postgres
DB_PASSWORD=[YOUR-PASSWORD]
DB_HOST=[PROJECT-REF].supabase.co
DB_PORT=5432
DB_NAME=postgres
```

## Running the Migration

### Using Supabase Dashboard

1. Go to your Supabase project
2. Navigate to **SQL Editor**
3. Copy the contents of `migrations/001_create_agent_runs_tables.sql`
4. Paste and run the SQL

### Using psql Command Line

```bash
psql "postgresql://postgres:[PASSWORD]@[PROJECT-REF].supabase.co:5432/postgres" \
  -f red-team-agent/migrations/001_create_agent_runs_tables.sql
```

### Using Python Script

You can also create a simple script to run the migration:

```python
from red_team_agent.supabase_client import get_db
from pathlib import Path

migration_file = Path(__file__).parent / "migrations" / "001_create_agent_runs_tables.sql"
with open(migration_file, 'r') as f:
    sql = f.read()

with get_db() as conn:
    with conn.cursor() as cur:
        cur.execute(sql)
    conn.commit()
```

## Verification

After setting up the connection, you can verify it works:

```python
from red_team_agent.supabase_client import is_connected, insert_red_team_run

if is_connected():
    print("✅ Database connection successful!")
    # Test insert
    result = insert_red_team_run("test_123", "openai/gpt-4o", "http://test.com", True)
    print(f"Test insert result: {result}")
else:
    print("❌ Database connection not configured")
```

## Automatic Logging

Once the database is configured, the following will automatically save to the database:

1. **Red Team Agent**: When `AgentLogger.save_report()` is called, it saves to `red_team_agent_runs`
2. **Auditor**: When `AuditorAgent.audit()` completes, it saves to `auditor_runs`
3. **TTP Master**: When `TTPLogger.save_report()` is called, it saves to `ttp_master_runs`

All database operations are optional - if the connection is not configured, the agents will continue to work normally and only save to local files.

## Query Examples

### Get all runs for a website
```sql
SELECT * FROM red_team_agent_runs 
WHERE url = 'http://localhost:3004' 
ORDER BY timestamp DESC;
```

### Get runs with auditor results
```sql
SELECT 
  r.run_id,
  r.url,
  r.model,
  a.expected_vulnerability,
  a.auditor_judgement
FROM red_team_agent_runs r
LEFT JOIN auditor_runs a ON r.run_id = a.run_id
ORDER BY r.timestamp DESC;
```

### Get all TTPs found for a run
```sql
SELECT ttp_found 
FROM ttp_master_runs 
WHERE run_id = '20251122_204639';
```

### Success rate by vulnerability type
```sql
SELECT 
  expected_vulnerability,
  COUNT(*) as total_runs,
  COUNT(*) FILTER (WHERE auditor_judgement = 'success') as successful,
  ROUND(100.0 * COUNT(*) FILTER (WHERE auditor_judgement = 'success') / COUNT(*), 2) as success_rate
FROM auditor_runs
GROUP BY expected_vulnerability
ORDER BY total_runs DESC;
```

