# SQL Injection Detection from Analytics - Best Practices

## Overview

This guide outlines the best methods to detect SQL injection attacks from website analytics, leveraging your existing logging infrastructure and additional detection strategies.

## 1. Direct Detection from Vulnerability Logs (Primary Method)

Your system already logs SQL injection attempts to Supabase `vulnerability_logs` table. This is the **most reliable** detection method.

### Key Detection Queries

#### A. Real-Time Detection
```sql
-- Get all SQL injection attempts in the last hour
SELECT 
  timestamp,
  attacker_id,
  sql_payload,
  vulnerable_query,
  session_id,
  base_url,
  path
FROM vulnerability_logs
WHERE vulnerability_type = 'sql-injection-attempt'
  AND timestamp >= NOW() - INTERVAL '1 hour'
ORDER BY timestamp DESC;
```

#### B. Suspicious Pattern Detection
```sql
-- Detect suspicious SQL injection patterns
SELECT 
  timestamp,
  attacker_id,
  sql_payload,
  suspicious_reason,
  session_id
FROM vulnerability_logs
WHERE vulnerability_type = 'sql-injection-suspicious'
ORDER BY timestamp DESC;
```

#### C. Attacker Profiling
```sql
-- Identify repeat attackers
SELECT 
  attacker_id,
  COUNT(*) as attempt_count,
  COUNT(DISTINCT session_id) as unique_sessions,
  MIN(timestamp) as first_attempt,
  MAX(timestamp) as last_attempt,
  array_agg(DISTINCT sql_payload) as payloads_used
FROM vulnerability_logs
WHERE vulnerability_type LIKE 'sql-injection%'
GROUP BY attacker_id
HAVING COUNT(*) > 1
ORDER BY attempt_count DESC;
```

#### D. Payload Analysis
```sql
-- Most common SQL injection payloads
SELECT 
  sql_payload,
  COUNT(*) as usage_count,
  COUNT(DISTINCT attacker_id) as unique_attackers
FROM vulnerability_logs
WHERE vulnerability_type = 'sql-injection-attempt'
  AND sql_payload IS NOT NULL
GROUP BY sql_payload
ORDER BY usage_count DESC
LIMIT 20;
```

#### E. Time-Based Analysis
```sql
-- SQL injection attempts by hour of day
SELECT 
  EXTRACT(HOUR FROM timestamp) as hour_of_day,
  COUNT(*) as attempt_count
FROM vulnerability_logs
WHERE vulnerability_type LIKE 'sql-injection%'
GROUP BY hour_of_day
ORDER BY hour_of_day;
```

## 2. Application-Level Analytics Detection

### A. Request Pattern Analysis

**Detect unusual request patterns:**

```sql
-- Requests with unusually long parameters (potential SQL injection)
SELECT 
  timestamp,
  attacker_id,
  sql_payload,
  LENGTH(sql_payload) as payload_length
FROM vulnerability_logs
WHERE vulnerability_type = 'sql-injection-attempt'
  AND LENGTH(sql_payload) > 50  -- Adjust threshold
ORDER BY payload_length DESC;
```

**Key Indicators:**
- Parameter length > 100 characters
- Multiple SQL keywords in single request
- Unusual character combinations (`'`, `--`, `;`, `UNION`)

### B. Response Pattern Analysis

**Detect successful injections:**

```sql
-- Successful SQL injections (returned data)
SELECT 
  timestamp,
  attacker_id,
  sql_payload,
  vulnerable_query
FROM vulnerability_logs
WHERE vulnerability_type = 'sql-injection-attempt'
  AND success = true  -- If your schema tracks success
ORDER BY timestamp DESC;
```

**Response Indicators:**
- Unusually large result sets
- Response contains SQL error messages
- Response time anomalies (slow queries)

## 3. Database Query Analytics

### A. Query Monitoring

Monitor actual database queries for:
- **Unusual query patterns**: Queries with dynamic WHERE clauses
- **Performance anomalies**: Queries taking > 1 second
- **Error rates**: SQL syntax errors in logs

### B. Query Pattern Detection

Look for these patterns in database logs:
- Queries with string concatenation
- Queries with `OR 1=1` or similar tautologies
- UNION-based queries
- Comment-based injections (`--`, `/* */`)

## 4. Web Server/API Analytics

### A. HTTP Request Analysis

**Key indicators in HTTP logs:**

1. **Request Body Analysis**
   - Look for SQL keywords in POST bodies
   - Monitor parameter values for injection patterns
   - Track unusual parameter names

2. **Status Code Patterns**
   - 500 errors may indicate SQL syntax errors
   - 200 responses with unusual data may indicate successful injection

3. **Request Timing**
   - Slow responses (> 2 seconds) may indicate complex SQL queries
   - Time-based blind SQL injection attempts

### B. User-Agent and Header Analysis

```sql
-- Correlate SQL injection attempts with user agents
SELECT 
  attacker_id,
  user_agent,
  COUNT(*) as attempt_count
FROM vulnerability_logs
WHERE vulnerability_type LIKE 'sql-injection%'
  AND user_agent IS NOT NULL
GROUP BY attacker_id, user_agent
ORDER BY attempt_count DESC;
```

## 5. Behavioral Analytics

### A. Session Analysis

**Detect automated attacks:**

```sql
-- Identify rapid-fire SQL injection attempts (bot behavior)
SELECT 
  attacker_id,
  session_id,
  COUNT(*) as attempts_in_session,
  MAX(timestamp) - MIN(timestamp) as session_duration
FROM vulnerability_logs
WHERE vulnerability_type LIKE 'sql-injection%'
GROUP BY attacker_id, session_id
HAVING COUNT(*) > 5  -- Multiple attempts in short time
ORDER BY attempts_in_session DESC;
```

### B. Geographic Analysis

```sql
-- SQL injection attempts by IP range (if you have geo data)
SELECT 
  attacker_id,
  COUNT(*) as attempt_count,
  COUNT(DISTINCT sql_payload) as unique_payloads
FROM vulnerability_logs
WHERE vulnerability_type LIKE 'sql-injection%'
GROUP BY attacker_id
ORDER BY attempt_count DESC;
```

## 6. Detection Patterns to Monitor

### High-Confidence Indicators

1. **Direct SQL Keywords**
   - `UNION SELECT`
   - `OR 1=1`
   - `'; DROP TABLE`
   - `EXEC(`

2. **SQL Comment Patterns**
   - `--` (single line comments)
   - `/* */` (multi-line comments)

3. **Quote Manipulation**
   - Unmatched quotes (`'`, `"`, `` ` ``)
   - Quote escaping attempts

4. **Command Chaining**
   - Semicolon followed by SQL commands (`; SELECT`, `; DROP`)

### Medium-Confidence Indicators

1. **Suspicious Character Combinations**
   - Multiple quotes in parameter
   - Mix of quotes and SQL keywords
   - Command separators (`;`, `|`, `&`)

2. **Unusual Parameter Lengths**
   - Parameters > 200 characters
   - Parameters with no alphanumeric content

## 7. Alerting Recommendations

### Real-Time Alerts

Set up alerts for:
- **Critical**: Any `sql-injection-attempt` detection
- **High**: Multiple attempts from same IP in < 5 minutes
- **Medium**: Suspicious patterns detected

### Alert Query Example

```sql
-- Get recent SQL injection attempts for alerting
SELECT 
  timestamp,
  attacker_id,
  vulnerability_type,
  sql_payload,
  base_url,
  path
FROM vulnerability_logs
WHERE vulnerability_type LIKE 'sql-injection%'
  AND timestamp >= NOW() - INTERVAL '5 minutes'
ORDER BY timestamp DESC;
```

## 8. Integration with Dashboard

Your dashboard backend (`dashboard/backend/app/main.py`) already queries these logs. Enhance it with:

### A. SQL Injection-Specific Endpoint

```python
@app.get("/api/sql-injection-attacks")
async def get_sql_injection_attacks(
    limit: int = 100,
    time_window: str = "24h"
):
    """Get SQL injection specific attacks"""
    # Query vulnerability_logs for sql-injection types
    # Filter by time window
    # Return structured data
```

### B. Detection Statistics

```python
@app.get("/api/sql-injection-stats")
async def get_sql_injection_stats():
    """Get SQL injection detection statistics"""
    # Count attempts by type
    # Most common payloads
    # Top attacking IPs
    # Success rate
```

## 9. Best Practices Summary

### ✅ DO

1. **Monitor vulnerability_logs table** - Your primary detection source
2. **Track both confirmed and suspicious** attempts
3. **Correlate by IP address** - Identify repeat attackers
4. **Analyze payload patterns** - Understand attack vectors
5. **Monitor response patterns** - Detect successful injections
6. **Set up real-time alerts** - Immediate notification

### ❌ DON'T

1. **Rely solely on pattern matching** - Use multiple detection methods
2. **Ignore suspicious patterns** - They may indicate reconnaissance
3. **Only monitor confirmed attacks** - Suspicious patterns are valuable
4. **Forget to analyze successful injections** - They indicate actual vulnerability exploitation

## 10. Advanced Detection Strategies

### A. Machine Learning-Based Detection

- Train models on historical SQL injection patterns
- Detect anomalies in request patterns
- Identify new attack vectors

### B. Honeypot Integration

Your system already uses honeypots. Enhance detection by:
- Tracking which honeypots are triggered
- Analyzing attacker behavior after detection
- Correlating with other attack types

### C. MITRE ATT&CK Correlation

Your logs include `technique_id` (T1190 for SQL injection). Use this to:
- Correlate SQL injection with other attack techniques
- Track attack campaigns
- Understand attacker progression

## 11. Example Detection Workflow

1. **Real-Time Monitoring**: Query `vulnerability_logs` every minute
2. **Pattern Analysis**: Check for SQL injection patterns
3. **Alert Generation**: Trigger alerts for confirmed attempts
4. **Investigation**: Analyze payload, IP, and session data
5. **Response**: Block IP, update WAF rules, patch vulnerability

## 12. SQL Injection Payload Patterns

Your system detects these patterns (from `honeypot-utils.ts`):

- `' OR '1'='1` - Boolean-based injection
- `' OR '1'='1'--` - Comment-based injection
- `UNION SELECT` - Union-based injection
- `'; DROP TABLE` - Destructive injection
- `xp_*` - SQL Server extended procedures
- `sp_*` - SQL Server stored procedures
- `EXEC()` - Command execution

## Conclusion

The **best way** to detect SQL injection from analytics is:

1. **Primary**: Query your `vulnerability_logs` table in Supabase
2. **Secondary**: Monitor application logs for SQL errors
3. **Tertiary**: Analyze request/response patterns
4. **Advanced**: Use behavioral analytics and ML

Your existing infrastructure already provides excellent detection capabilities through the `logSqlInjectionAttempt` function. Focus on querying and analyzing the `vulnerability_logs` table for the most reliable detection.

