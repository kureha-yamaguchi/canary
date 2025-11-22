-- Drop existing tables if they exist
DROP TABLE IF EXISTS tactics CASCADE;
DROP TABLE IF EXISTS techniques CASCADE;

-- Create the parent table for MITRE ATT&CK techniques
CREATE TABLE techniques (
  technique_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  url TEXT,
  domain TEXT
);

-- Create the tactics table with composite primary key
CREATE TABLE tactics (
  technique_id TEXT NOT NULL REFERENCES techniques(technique_id) ON DELETE CASCADE,
  tactic TEXT NOT NULL,
  PRIMARY KEY (technique_id, tactic)
);

-- Create an index on tactic for filtering by tactic type
CREATE INDEX idx_tactics_tactic ON tactics(tactic);

-- Enable Row Level Security
ALTER TABLE techniques ENABLE ROW LEVEL SECURITY;
ALTER TABLE tactics ENABLE ROW LEVEL SECURITY;

-- Create policies to allow public read access
CREATE POLICY "Allow public read access on techniques"
  ON techniques
  FOR SELECT
  USING (true);

CREATE POLICY "Allow public read access on tactics"
  ON tactics
  FOR SELECT
  USING (true);
