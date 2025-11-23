-- Migration: Create agent runs tables
-- Created: 2025-11-22
-- Description: Creates tables for red_team_agent_runs, auditor_runs, and ttp_master_runs

-- Table 1: red_team_agent_runs
CREATE TABLE IF NOT EXISTS red_team_agent_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id VARCHAR(50) NOT NULL UNIQUE,
  model VARCHAR(100) NOT NULL,
  url TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  success BOOLEAN NOT NULL DEFAULT true,
  
  CONSTRAINT red_team_agent_runs_run_id_key UNIQUE (run_id)
);

-- Table 2: auditor_runs
CREATE TABLE IF NOT EXISTS auditor_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id VARCHAR(50) NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expected_vulnerability VARCHAR(100) NOT NULL,
  auditor_judgement VARCHAR(20) NOT NULL CHECK (auditor_judgement IN ('success', 'failure')),
  
  CONSTRAINT auditor_runs_run_id_fkey FOREIGN KEY (run_id) 
    REFERENCES red_team_agent_runs(run_id) ON DELETE CASCADE
);

-- Table 3: ttp_master_runs
CREATE TABLE IF NOT EXISTS ttp_master_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id VARCHAR(50) NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ttp_found VARCHAR(50) NOT NULL,
  
  CONSTRAINT ttp_master_runs_run_id_fkey FOREIGN KEY (run_id) 
    REFERENCES red_team_agent_runs(run_id) ON DELETE CASCADE
);

-- Indexes for red_team_agent_runs
CREATE INDEX IF NOT EXISTS idx_red_team_agent_runs_timestamp ON red_team_agent_runs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_red_team_agent_runs_url ON red_team_agent_runs(url);
CREATE INDEX IF NOT EXISTS idx_red_team_agent_runs_model ON red_team_agent_runs(model);
CREATE INDEX IF NOT EXISTS idx_red_team_agent_runs_success ON red_team_agent_runs(success);

-- Indexes for auditor_runs
CREATE INDEX IF NOT EXISTS idx_auditor_runs_run_id ON auditor_runs(run_id);
CREATE INDEX IF NOT EXISTS idx_auditor_runs_timestamp ON auditor_runs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_auditor_runs_expected_vulnerability ON auditor_runs(expected_vulnerability);
CREATE INDEX IF NOT EXISTS idx_auditor_runs_judgement ON auditor_runs(auditor_judgement);

-- Indexes for ttp_master_runs
CREATE INDEX IF NOT EXISTS idx_ttp_master_runs_run_id ON ttp_master_runs(run_id);
CREATE INDEX IF NOT EXISTS idx_ttp_master_runs_timestamp ON ttp_master_runs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ttp_master_runs_ttp_found ON ttp_master_runs(ttp_found);

