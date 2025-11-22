-- Drop existing tables if they exist
DROP TABLE IF EXISTS vulnerability_logs CASCADE;
DROP TABLE IF EXISTS vulnerability_types CASCADE;

-- Create vulnerability types reference table
CREATE TABLE vulnerability_types (
    vulnerability_type TEXT PRIMARY KEY,
    difficulty INTEGER
);

-- Create main vulnerability log table
CREATE TABLE vulnerability_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    base_url TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL REFERENCES vulnerability_types(vulnerability_type) ON DELETE CASCADE,
    technique_id TEXT NOT NULL REFERENCES techniques(technique_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attacker_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    CONSTRAINT valid_url CHECK (base_url ~ '^https?://')
);

-- Create function to auto-create vulnerability types
CREATE OR REPLACE FUNCTION auto_create_vulnerability_type()
RETURNS TRIGGER AS $$
BEGIN
    -- Insert the vulnerability type if it doesn't exist
    INSERT INTO vulnerability_types (vulnerability_type, difficulty)
    VALUES (NEW.vulnerability_type, NULL)
    ON CONFLICT (vulnerability_type) DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger to auto-create vulnerability types before insert
CREATE TRIGGER auto_create_vulnerability_type_trigger
    BEFORE INSERT ON vulnerability_logs
    FOR EACH ROW
    EXECUTE FUNCTION auto_create_vulnerability_type();

-- Create indexes
CREATE INDEX idx_vulnerability_logs_base_url ON vulnerability_logs(base_url);
CREATE INDEX idx_vulnerability_logs_vulnerability_type ON vulnerability_logs(vulnerability_type);
CREATE INDEX idx_vulnerability_logs_technique_id ON vulnerability_logs(technique_id);
CREATE INDEX idx_vulnerability_logs_timestamp ON vulnerability_logs(timestamp DESC);
CREATE INDEX idx_vulnerability_logs_attacker_id ON vulnerability_logs(attacker_id);
CREATE INDEX idx_vulnerability_logs_session_id ON vulnerability_logs(session_id);

-- Enable RLS on vulnerability_types
ALTER TABLE vulnerability_types ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow read access to vulnerability types"
    ON vulnerability_types FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Service role can manage vulnerability types"
    ON vulnerability_types FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- Enable RLS on vulnerability_logs
ALTER TABLE vulnerability_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow read access to vulnerability logs"
    ON vulnerability_logs FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Allow insert vulnerability logs"
    ON vulnerability_logs FOR INSERT
    TO authenticated
    WITH CHECK (true);

CREATE POLICY "Service role can manage vulnerability logs"
    ON vulnerability_logs FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
