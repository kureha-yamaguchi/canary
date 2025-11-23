# Vulnerability Detection Database Schema

## Purpose
Logs detected vulnerabilities from web security scanning, tracking what was found, where, when, and by whom.

## Tables

### `vulnerability_logs` (main table)
Primary log of all detected vulnerabilities.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | Yes (auto) | Primary key, auto-generated |
| `base_url` | TEXT | Yes | Website URL (must start with http:// or https://) |
| `path` | TEXT | No | Specific path on the website (optional) |
| `vulnerability_type` | TEXT | Yes | Type of vulnerability detected |
| `timestamp` | TIMESTAMPTZ | Yes (auto) | When vulnerability was detected (defaults to NOW()) |
| `attack_id` | TEXT | No | Identifier for the attacker (IP address, session ID, etc.) |

**Indexes:** `base_url`, `vulnerability_type`, `timestamp DESC`, `attack_id` (partial)

### `vulnerability_types` (reference table)
Catalog of vulnerability types with metadata.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vulnerability_type` | TEXT | Yes | Primary key, name of vulnerability |
| `difficulty` | INTEGER | No | Exploitation difficulty level |

## Key Behaviors

**Auto-upsert vulnerability types:** When inserting a log with a new `vulnerability_type`, a corresponding entry is automatically created in `vulnerability_types` with `difficulty = NULL`. You can update the difficulty later.

**Row Level Security (RLS):**
- Authenticated users can read both tables and insert into `vulnerability_logs`
- Service role has full access to both tables

## Usage Example

```sql
-- Insert a new vulnerability log
INSERT INTO vulnerability_logs (base_url, path, vulnerability_type, attack_id)
VALUES ('https://example.com', '/admin', 'sql_injection', '192.168.1.1');

-- The vulnerability_type 'sql_injection' is automatically created if it doesn't exist

-- Later, update the difficulty
UPDATE vulnerability_types 
SET difficulty = 7 
WHERE vulnerability_type = 'sql_injection';
```