import { HONEYPOT_CONFIG } from './honeypot-config';
import { supabase, VulnerabilityLog } from './supabase';

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
 * Only logs when SQL injection is actually detected (not for suspicious or normal requests)
 */
export async function logSqlInjectionAttempt(
  result: SqlInjectionCheckResult,
  request: Request,
  route?: string
) {
  // Only log when SQL injection is actually detected
  if (result.status !== 'injection_detected') {
    console.log(`[Honeypot] Skipping log for status: ${result.status} (only logging injection_detected)`);
    return;
  }

  const url = new URL(request.url);

  // Use consistent vulnerability type for SQL injection
  const vulnerabilityType = 'SQL_INJECTION';

  // Extract attacker_id (IP address or other identifier)
  const attackerId =
    request.headers.get('x-forwarded-for')?.split(',')[0] ||
    request.headers.get('x-real-ip') ||
    'unknown';

  // Get session ID for tracking
  const sessionId = getSessionId(request);

  // Get appropriate MITRE ATT&CK technique ID
  const techniqueId = getTechniqueId(vulnerabilityType);

  // Build the path (include route if provided, otherwise use URL pathname)
  const path = route || url.pathname;

  const payload: VulnerabilityLog = {
    base_url: url.origin,
    path: path,
    vulnerability_type: vulnerabilityType,
    technique_id: techniqueId,
    attacker_id: attackerId,
    session_id: sessionId,
  };

  console.log('[Honeypot] Attempting to log SQL injection to vulnerability_logs:', {
    ...payload,
    sql_payload: result.payload,
    vulnerable_query: result.query,
  });

  // Check if Supabase is configured
  if (!supabase) {
    console.warn('[Honeypot] Supabase not configured - skipping database log. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env.local');
    return;
  }

  try {
    // First, ensure the technique exists in the techniques table
    // This handles the foreign key constraint requirement
    const { error: techniqueError } = await supabase
      .from('techniques')
      .upsert(
        {
          technique_id: techniqueId,
          name: 'Exploit Public-Facing Application',
          description: 'Attackers exploit vulnerabilities in internet-facing web servers, including SQL injection attacks',
          domain: 'enterprise',
        },
        {
          onConflict: 'technique_id',
          ignoreDuplicates: false,
        }
      );

    if (techniqueError) {
      console.warn('[Honeypot] Could not ensure technique exists (may already exist):', techniqueError);
      // Continue anyway - the technique might already exist
    }

    // Try inserting with path first
    let insertPayload = payload;
    let { data, error } = await supabase
      .from('vulnerability_logs')
      .insert(insertPayload);

    // If error is due to path column not existing, try without it
    if (error && (error.code === 'PGRST116' || error.message?.includes('column') || error.message?.includes('path'))) {
      console.warn('[Honeypot] Retrying insert without path field (column may not exist)');
      const { path, ...payloadWithoutPath } = payload;
      insertPayload = payloadWithoutPath;
      ({ data, error } = await supabase
        .from('vulnerability_logs')
        .insert(insertPayload));
    }

    if (error) {
      console.error('[Honeypot] Failed to log SQL injection to Supabase:');
      console.error('[Honeypot] Error code:', error.code);
      console.error('[Honeypot] Error message:', error.message);
      console.error('[Honeypot] Error details:', error.details);
      console.error('[Honeypot] Error hint:', error.hint);
      console.error('[Honeypot] Payload attempted:', JSON.stringify(insertPayload, null, 2));
      console.error('[Honeypot] Full error:', JSON.stringify(error, null, 2));
    } else {
      console.log('[Honeypot] ✅ Successfully logged SQL injection to vulnerability_logs table');
      console.log('[Honeypot] Log ID:', data?.[0]?.id || 'unknown');
      console.log('[Honeypot] Logged data:', JSON.stringify(data, null, 2));
    }
  } catch (err) {
    console.error('[Honeypot] Exception while logging SQL injection:', err);
    if (err instanceof Error) {
      console.error('[Honeypot] Exception message:', err.message);
      console.error('[Honeypot] Exception stack:', err.stack);
    }
  }
}

