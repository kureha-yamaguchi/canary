import { HONEYPOT_CONFIG } from './honeypot-config';
import { supabase } from './supabase';

export type SqlInjectionCheckResult =
  | { status: 'injection_detected'; payload: string; query: string }
  | { status: 'suspicious'; payload: string; reason: string }
  | { status: 'normal'; payload: string };

/**
 * Check if user input contains SQL injection patterns
 */
export function checkSqlInjection(input: string): SqlInjectionCheckResult {
  const payload = input.trim();
  
  // SQL injection patterns to detect
  const sqlInjectionPatterns = [
    /(['"`])\s*(OR|AND)\s*\1\s*=\s*\1/i,  // ' OR '1'='1
    /(['"`])\s*(OR|AND)\s*\1\s*=\s*\1\s*--/i,  // ' OR '1'='1'--
    /(['"`])\s*;\s*DROP\s+TABLE/i,  // '; DROP TABLE
    /UNION\s+SELECT/i,  // UNION SELECT
    /OR\s+1\s*=\s*1/i,  // OR 1=1
    /OR\s+1\s*=\s*1\s*--/i,  // OR 1=1--
    /'\s*OR\s*'1'\s*=\s*'1/i,  // ' OR '1'='1
    /'\s*OR\s*'1'\s*=\s*'1'\s*--/i,  // ' OR '1'='1'--
    /\/\*.*\*\//,  // SQL comments /* */
    /--\s/,  // SQL comments --
    /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/i,  // Command chaining
    /xp_\w+/i,  // SQL Server extended procedures
    /EXEC\s*\(/i,  // EXEC()
    /sp_\w+/i,  // SQL Server stored procedures
  ];

  // Check for SQL injection patterns
  for (const pattern of sqlInjectionPatterns) {
    if (pattern.test(payload)) {
      // Simulate the vulnerable SQL query (for logging purposes)
      const vulnerableQuery = `SELECT * FROM ${HONEYPOT_CONFIG.tableName} WHERE username = '${payload}' AND password = '...'`;
      
      return {
        status: 'injection_detected',
        payload,
        query: vulnerableQuery,
      };
    }
  }

  // Check for suspicious patterns (less definitive)
  const suspiciousPatterns = [
    /['"`]/,  // Quotes
    /[;|&]/,  // Command separators
    /(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/i,  // SQL keywords
  ];

  let suspiciousCount = 0;
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(payload)) {
      suspiciousCount++;
    }
  }

  if (suspiciousCount >= 2) {
    return {
      status: 'suspicious',
      payload,
      reason: 'Multiple suspicious patterns detected',
    };
  }

  return {
    status: 'normal',
    payload,
  };
}

/**
 * Map vulnerability types to MITRE ATT&CK technique IDs
 * 
 * This honeypot exposes Vulnerability ID 1: "SQL Injection"
 * See docs/vulnerability-mapping.txt for complete mapping details.
 * 
 * MITRE ATT&CK Technique Mappings:
 * - T1190: Exploit Public-Facing Application - SQL injection attacks
 */
function getTechniqueId(vulnerabilityType: string): string {
  // T1190: Exploit Public-Facing Application - SQL injection through user input
  return 'T1190';
}

/**
 * Generate a session ID from request headers
 */
function getSessionId(request: Request): string {
  const ip = request.headers.get('x-forwarded-for') ||
             request.headers.get('x-real-ip') ||
             'unknown';
  const timestamp = Date.now();
  return `${ip.split(',')[0]}_${timestamp}`;
}

/**
 * Log SQL injection attempt to Supabase database
 */
export async function logSqlInjectionAttempt(
  result: SqlInjectionCheckResult,
  request: Request,
  route?: string
) {
  const url = new URL(request.url);

  // Map the result status to specific vulnerability types
  const vulnerabilityType =
    result.status === 'injection_detected'
      ? 'sql-injection-attempt'
      : result.status === 'suspicious'
      ? 'sql-injection-suspicious'
      : 'sql-injection-normal';

  // Extract attacker_id (IP address or other identifier)
  const attackerId =
    request.headers.get('x-forwarded-for')?.split(',')[0] ||
    request.headers.get('x-real-ip') ||
    'unknown';

  // Get session ID for tracking
  const sessionId = getSessionId(request);

  // Get appropriate MITRE ATT&CK technique ID
  const techniqueId = getTechniqueId(vulnerabilityType);

  const payload = {
    base_url: url.origin,
    vulnerability_type: vulnerabilityType,
    technique_id: techniqueId,
    attacker_id: attackerId,
    session_id: sessionId,
  };

  // Add additional context for SQL injection
  if (result.status === 'injection_detected') {
    (payload as any).sql_payload = result.payload;
    (payload as any).vulnerable_query = result.query;
  } else if (result.status === 'suspicious') {
    (payload as any).sql_payload = result.payload;
    (payload as any).suspicious_reason = result.reason;
  }

  console.log('[Honeypot] Attempting to log SQL injection to Supabase:', payload);

  // Check if Supabase is configured
  if (!supabase) {
    console.warn('[Honeypot] Supabase not configured - skipping database log. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env.local');
    return;
  }

  try {
    const { data, error } = await supabase
      .from('vulnerability_logs')
      .insert(payload);

    if (error) {
      console.error('[Honeypot] Failed to log to Supabase:', error);
    } else {
      console.log('[Honeypot] Successfully logged to Supabase:', data);
    }
  } catch (err) {
    console.error('[Honeypot] Exception while logging:', err);
  }
}

