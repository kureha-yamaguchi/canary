-- Migration: Create multi-website builder runs table
-- Created: 2025-11-23
-- Description: Creates table for tracking multi-website builder runs

-- Table: multi_website_builder_runs
CREATE TABLE IF NOT EXISTS multi_website_builder_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  model VARCHAR(100) NOT NULL,
  vulnerability_id INTEGER NOT NULL,
  website_prompt_id INTEGER NOT NULL,
  building_success BOOLEAN NOT NULL DEFAULT false,
  supabase_connection_success BOOLEAN NOT NULL DEFAULT false
);

-- Indexes for multi_website_builder_runs
CREATE INDEX IF NOT EXISTS idx_multi_website_builder_runs_timestamp ON multi_website_builder_runs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_multi_website_builder_runs_model ON multi_website_builder_runs(model);
CREATE INDEX IF NOT EXISTS idx_multi_website_builder_runs_vulnerability_id ON multi_website_builder_runs(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_multi_website_builder_runs_website_prompt_id ON multi_website_builder_runs(website_prompt_id);
CREATE INDEX IF NOT EXISTS idx_multi_website_builder_runs_building_success ON multi_website_builder_runs(building_success);
CREATE INDEX IF NOT EXISTS idx_multi_website_builder_runs_supabase_connection_success ON multi_website_builder_runs(supabase_connection_success);

