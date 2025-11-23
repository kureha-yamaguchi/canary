-- Migration: Add mapping_type and mapping_rationale to ttp_master_runs
-- Created: 2025-11-23
-- Description: Adds mapping_type and mapping_rationale columns to ttp_master_runs table

-- Add new columns
ALTER TABLE ttp_master_runs 
ADD COLUMN IF NOT EXISTS mapping_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS mapping_rationale TEXT;

-- Update existing rows to have default values (optional, for existing data)
UPDATE ttp_master_runs 
SET mapping_type = 'unknown', mapping_rationale = 'No rationale provided'
WHERE mapping_type IS NULL;

-- Add index for mapping_type
CREATE INDEX IF NOT EXISTS idx_ttp_master_runs_mapping_type ON ttp_master_runs(mapping_type);

