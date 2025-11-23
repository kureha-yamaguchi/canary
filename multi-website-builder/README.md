# Multi-Website Builder

An automated tool that generates websites using an LLM. Uses a base prompt template with configurable sections to specify the website type and vulnerability type, enabling rapid generation of test websites for security assessment.

## Database Setup

The multi-website builder can log build runs to a Supabase database table for tracking and analytics.

### Table: `multi_website_builder_runs`

The table tracks:
- `timestamp` - When the build was run
- `model` - LLM model used for building (e.g., "google/gemini-3-pro-preview")
- `vulnerability_id` - ID of the vulnerability being tested
- `website_prompt_id` - ID of the website prompt used
- `building_success` - Whether the website build succeeded
- `supabase_connection_success` - Whether Supabase connection was successful

### Running the Migration

#### Option 1: Using Python Script (Recommended)

```bash
cd multi-website-builder
python3 run_migration.py
```

This script will:
- Try to use Supabase REST API if `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are set
- Fall back to direct PostgreSQL connection if `DATABASE_URL` is set
- Provide instructions if neither is configured

#### Option 2: Using Supabase Dashboard

1. Go to your Supabase project
2. Navigate to **SQL Editor**
3. Copy the contents of `migrations/001_create_multi_website_builder_runs_table.sql`
4. Paste and run the SQL

#### Option 3: Using psql Command Line

```bash
psql "postgresql://postgres:[PASSWORD]@[PROJECT-REF].supabase.co:5432/postgres" \
  -f multi-website-builder/migrations/001_create_multi_website_builder_runs_table.sql
```

### Environment Variables

The migration script and logging require one of these configurations:

**Option A: Supabase REST API**
```env
SUPABASE_URL=https://[PROJECT-REF].supabase.co
SUPABASE_SERVICE_ROLE_KEY=[YOUR-SERVICE-ROLE-KEY]
```

**Option B: Direct PostgreSQL Connection**
```env
DATABASE_URL=postgresql://postgres:[PASSWORD]@[PROJECT-REF].supabase.co:5432/postgres
```

### Using the Database Logger

After running the migration, you can use the `supabase_client.py` module to log builds:

```python
from supabase_client import insert_builder_run, is_connected

if is_connected():
    result = insert_builder_run(
        model="google/gemini-3-pro-preview",
        vulnerability_id=1,
        website_prompt_id=1,
        building_success=True,
        supabase_connection_success=True
    )
    print(f"Logged build run: {result}")
```

### Query Examples

```sql
-- Get all successful builds
SELECT * FROM multi_website_builder_runs 
WHERE building_success = true 
ORDER BY timestamp DESC;

-- Get builds by vulnerability
SELECT * FROM multi_website_builder_runs 
WHERE vulnerability_id = 1 
ORDER BY timestamp DESC;

-- Success rate by model
SELECT 
  model,
  COUNT(*) as total_builds,
  COUNT(*) FILTER (WHERE building_success = true) as successful,
  ROUND(100.0 * COUNT(*) FILTER (WHERE building_success = true) / COUNT(*), 2) as success_rate
FROM multi_website_builder_runs
GROUP BY model
ORDER BY total_builds DESC;
```
