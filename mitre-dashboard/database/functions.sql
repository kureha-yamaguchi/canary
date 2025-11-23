-- Function to get attack histogram aggregated by time bucket and tactic
-- Handles one-to-many relationship (one technique can belong to multiple tactics)
CREATE OR REPLACE FUNCTION get_attack_histogram(
  time_range_minutes INT DEFAULT 1440,
  bucket_minutes INT DEFAULT 60,
  include_synthetic BOOLEAN DEFAULT false,
  filter_websites TEXT[] DEFAULT NULL,
  filter_vuln_types TEXT[] DEFAULT NULL,
  filter_techniques TEXT[] DEFAULT NULL,
  filter_ips TEXT[] DEFAULT NULL
)
RETURNS TABLE (
  time_bucket TIMESTAMP WITH TIME ZONE,
  tactic TEXT,
  tactic_name TEXT,
  attack_count BIGINT
) AS $$
BEGIN
  RETURN QUERY
  WITH filtered_attacks AS (
    SELECT
      v.timestamp,
      v.technique_id,
      v.base_url,
      v.vulnerability_type,
      v.attacker_id
    FROM vulnerability_logs v
    WHERE v.timestamp >= NOW() - (time_range_minutes || ' minutes')::INTERVAL
      AND (include_synthetic OR v.is_synthetic IS NULL OR v.is_synthetic = false)
      AND (filter_websites IS NULL OR v.base_url = ANY(filter_websites))
      AND (filter_vuln_types IS NULL OR v.vulnerability_type = ANY(filter_vuln_types))
      AND (filter_techniques IS NULL OR v.technique_id = ANY(filter_techniques))
      AND (filter_ips IS NULL OR v.attacker_id = ANY(filter_ips))
  ),
  time_buckets AS (
    SELECT
      date_trunc('hour', timestamp) +
        (EXTRACT(MINUTE FROM timestamp)::int / bucket_minutes) * (bucket_minutes || ' minutes')::INTERVAL
        as bucket_time,
      technique_id
    FROM filtered_attacks
  )
  SELECT
    tb.bucket_time as time_bucket,
    t.tactic,
    t.tactic as tactic_name,
    COUNT(*)::BIGINT as attack_count
  FROM time_buckets tb
  LEFT JOIN tactics t ON tb.technique_id = t.technique_id
  GROUP BY tb.bucket_time, t.tactic
  ORDER BY tb.bucket_time DESC, t.tactic;
END;
$$ LANGUAGE plpgsql;

-- Function to get summary stats (total count, success rate, unique targets, etc.)
CREATE OR REPLACE FUNCTION get_attack_stats(
  time_range_minutes INT DEFAULT 1440,
  include_synthetic BOOLEAN DEFAULT false,
  filter_websites TEXT[] DEFAULT NULL,
  filter_vuln_types TEXT[] DEFAULT NULL,
  filter_techniques TEXT[] DEFAULT NULL,
  filter_ips TEXT[] DEFAULT NULL
)
RETURNS JSON AS $$
DECLARE
  result JSON;
BEGIN
  SELECT json_build_object(
    'total_attacks', (
      SELECT COUNT(*)
      FROM vulnerability_logs v
      WHERE v.timestamp >= NOW() - (time_range_minutes || ' minutes')::INTERVAL
        AND (include_synthetic OR v.is_synthetic IS NULL OR v.is_synthetic = false)
        AND (filter_websites IS NULL OR v.base_url = ANY(filter_websites))
        AND (filter_vuln_types IS NULL OR v.vulnerability_type = ANY(filter_vuln_types))
        AND (filter_techniques IS NULL OR v.technique_id = ANY(filter_techniques))
        AND (filter_ips IS NULL OR v.attacker_id = ANY(filter_ips))
    ),
    'successful_attacks', (
      SELECT COUNT(*)
      FROM vulnerability_logs v
      WHERE v.timestamp >= NOW() - (time_range_minutes || ' minutes')::INTERVAL
        AND v.success = true
        AND (include_synthetic OR v.is_synthetic IS NULL OR v.is_synthetic = false)
        AND (filter_websites IS NULL OR v.base_url = ANY(filter_websites))
        AND (filter_vuln_types IS NULL OR v.vulnerability_type = ANY(filter_vuln_types))
        AND (filter_techniques IS NULL OR v.technique_id = ANY(filter_techniques))
        AND (filter_ips IS NULL OR v.attacker_id = ANY(filter_ips))
    ),
    'unique_targets', (
      SELECT COUNT(DISTINCT base_url)
      FROM vulnerability_logs v
      WHERE v.timestamp >= NOW() - (time_range_minutes || ' minutes')::INTERVAL
        AND (include_synthetic OR v.is_synthetic IS NULL OR v.is_synthetic = false)
        AND (filter_websites IS NULL OR v.base_url = ANY(filter_websites))
        AND (filter_vuln_types IS NULL OR v.vulnerability_type = ANY(filter_vuln_types))
        AND (filter_techniques IS NULL OR v.technique_id = ANY(filter_techniques))
        AND (filter_ips IS NULL OR v.attacker_id = ANY(filter_ips))
    ),
    'unique_techniques', (
      SELECT COUNT(DISTINCT technique_id)
      FROM vulnerability_logs v
      WHERE v.timestamp >= NOW() - (time_range_minutes || ' minutes')::INTERVAL
        AND (include_synthetic OR v.is_synthetic IS NULL OR v.is_synthetic = false)
        AND (filter_websites IS NULL OR v.base_url = ANY(filter_websites))
        AND (filter_vuln_types IS NULL OR v.vulnerability_type = ANY(filter_vuln_types))
        AND (filter_techniques IS NULL OR v.technique_id = ANY(filter_techniques))
        AND (filter_ips IS NULL OR v.attacker_id = ANY(filter_ips))
    )
  ) INTO result;

  RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Function to get filter options (unique values for dropdowns)
CREATE OR REPLACE FUNCTION get_filter_options(
  time_range_minutes INT DEFAULT 1440,
  include_synthetic BOOLEAN DEFAULT false
)
RETURNS JSON AS $$
DECLARE
  result JSON;
BEGIN
  SELECT json_build_object(
    'websites', (
      SELECT array_agg(DISTINCT base_url ORDER BY base_url)
      FROM vulnerability_logs v
      WHERE v.timestamp >= NOW() - (time_range_minutes || ' minutes')::INTERVAL
        AND (include_synthetic OR v.is_synthetic IS NULL OR v.is_synthetic = false)
    ),
    'vuln_types', (
      SELECT array_agg(DISTINCT vulnerability_type ORDER BY vulnerability_type)
      FROM vulnerability_logs v
      WHERE v.timestamp >= NOW() - (time_range_minutes || ' minutes')::INTERVAL
        AND (include_synthetic OR v.is_synthetic IS NULL OR v.is_synthetic = false)
    ),
    'techniques', (
      SELECT array_agg(DISTINCT technique_id ORDER BY technique_id)
      FROM vulnerability_logs v
      WHERE v.timestamp >= NOW() - (time_range_minutes || ' minutes')::INTERVAL
        AND (include_synthetic OR v.is_synthetic IS NULL OR v.is_synthetic = false)
    ),
    'ips', (
      SELECT array_agg(DISTINCT attacker_id ORDER BY attacker_id)
      FROM vulnerability_logs v
      WHERE v.timestamp >= NOW() - (time_range_minutes || ' minutes')::INTERVAL
        AND (include_synthetic OR v.is_synthetic IS NULL OR v.is_synthetic = false)
    )
  ) INTO result;

  RETURN result;
END;
$$ LANGUAGE plpgsql;
