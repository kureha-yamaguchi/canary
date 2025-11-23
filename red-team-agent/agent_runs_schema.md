# Agent Runs Database Schema

## Tables

### 1. `red_team_agent_runs`

Stores basic information about each red team agent execution.

```sql
CREATE TABLE red_team_agent_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id VARCHAR(50) NOT NULL UNIQUE,  -- Format: YYYYMMDD_HHMMSS
  model VARCHAR(100) NOT NULL,  -- e.g., 'openai/gpt-4o'
  url TEXT NOT NULL,  -- Target website URL
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  success BOOLEAN NOT NULL DEFAULT true,  -- Whether the run completed successfully
  
  CONSTRAINT red_team_agent_runs_run_id_key UNIQUE (run_id)
);

-- Indexes
CREATE INDEX idx_red_team_agent_runs_timestamp ON red_team_agent_runs(timestamp DESC);
CREATE INDEX idx_red_team_agent_runs_url ON red_team_agent_runs(url);
CREATE INDEX idx_red_team_agent_runs_model ON red_team_agent_runs(model);
CREATE INDEX idx_red_team_agent_runs_success ON red_team_agent_runs(success);
```

### 2. `auditor_runs`

Stores auditor analysis results for each agent run.

```sql
CREATE TABLE auditor_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id VARCHAR(50) NOT NULL,  -- References red_team_agent_runs.run_id
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expected_vulnerability VARCHAR(100) NOT NULL,  -- vulnerability_type from vulnerabilities.json (e.g., 'sql-injection', 'xss-reflected')
  auditor_judgement VARCHAR(20) NOT NULL,  -- 'success' or 'failure'
  
  CONSTRAINT auditor_runs_run_id_fkey FOREIGN KEY (run_id) 
    REFERENCES red_team_agent_runs(run_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_auditor_runs_run_id ON auditor_runs(run_id);
CREATE INDEX idx_auditor_runs_timestamp ON auditor_runs(timestamp DESC);
CREATE INDEX idx_auditor_runs_expected_vulnerability ON auditor_runs(expected_vulnerability);
CREATE INDEX idx_auditor_runs_judgement ON auditor_runs(auditor_judgement);
```

### 3. `ttp_master_runs`

Stores TTP (MITRE ATT&CK) findings. Multiple rows per run if multiple TTPs are found.

```sql
CREATE TABLE ttp_master_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id VARCHAR(50) NOT NULL,  -- References red_team_agent_runs.run_id
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ttp_found VARCHAR(50) NOT NULL,  -- MITRE TTP ID (e.g., 'T1190', 'T1552.001')
  
  CONSTRAINT ttp_master_runs_run_id_fkey FOREIGN KEY (run_id) 
    REFERENCES red_team_agent_runs(run_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_ttp_master_runs_run_id ON ttp_master_runs(run_id);
CREATE INDEX idx_ttp_master_runs_timestamp ON ttp_master_runs(timestamp DESC);
CREATE INDEX idx_ttp_master_runs_ttp_found ON ttp_master_runs(ttp_found);
```

## Field Descriptions

### red_team_agent_runs
- **run_id**: Unique identifier in format `YYYYMMDD_HHMMSS`
- **model**: The LLM model used (e.g., 'openai/gpt-4o')
- **url**: Target website URL being tested
- **timestamp**: When the run was executed
- **success**: Boolean indicating if the run completed successfully

### auditor_runs
- **run_id**: References the red_team_agent_runs.run_id
- **timestamp**: When the auditor analysis was performed
- **expected_vulnerability**: The vulnerability_type from vulnerabilities.json (e.g., 'sql-injection', 'xss-reflected', 'idor')
- **auditor_judgement**: 'success' if vulnerability was found, 'failure' if not found

### ttp_master_runs
- **run_id**: References the red_team_agent_runs.run_id
- **timestamp**: When the TTP analysis was performed
- **ttp_found**: MITRE ATT&CK technique ID (e.g., 'T1190', 'T1552.001')
- **Note**: Multiple rows can exist for the same run_id if multiple TTPs are found

## Query Examples

```sql
-- Get all runs for a specific URL
SELECT * FROM red_team_agent_runs WHERE url = 'http://localhost:3004' ORDER BY timestamp DESC;

-- Get runs with their auditor results
SELECT 
  r.run_id,
  r.url,
  r.model,
  r.timestamp,
  a.expected_vulnerability,
  a.auditor_judgement
FROM red_team_agent_runs r
LEFT JOIN auditor_runs a ON r.run_id = a.run_id
ORDER BY r.timestamp DESC;

-- Get all TTPs found for a specific run
SELECT ttp_found FROM ttp_master_runs WHERE run_id = '20251122_204639';

-- Get runs with TTP counts
SELECT 
  r.run_id,
  r.url,
  COUNT(t.ttp_found) as ttp_count,
  ARRAY_AGG(t.ttp_found) as ttps
FROM red_team_agent_runs r
LEFT JOIN ttp_master_runs t ON r.run_id = t.run_id
GROUP BY r.run_id, r.url
ORDER BY r.timestamp DESC;

-- Get success rate by vulnerability type
SELECT 
  expected_vulnerability,
  COUNT(*) as total_runs,
  COUNT(*) FILTER (WHERE auditor_judgement = 'success') as successful,
  ROUND(100.0 * COUNT(*) FILTER (WHERE auditor_judgement = 'success') / COUNT(*), 2) as success_rate
FROM auditor_runs
GROUP BY expected_vulnerability
ORDER BY total_runs DESC;
```
