import { HONEYPOT_CONFIG } from './honeypot-config';
import { supabase } from './supabase';
import { analyzeFingerprint, type FingerprintResult } from './fingerprint';

export type ApiKeyCheckResult =
  | { status: 'correct'; apiKey: string; header: string }
  | { status: 'wrong'; apiKey: string; header: string }
  | { status: 'none' };

/**
 * Check if request headers contain an API key and validate it
 * Returns the status (correct, wrong, or none) along with key details
 */
export function checkApiKey(headers: Headers): ApiKeyCheckResult {
  // Check all headers for any API key
  for (const [key, value] of headers.entries()) {
    if (value.includes('sk_') || key.toLowerCase().includes('api')) {
      // Check if it's the correct API key
      if (value === HONEYPOT_CONFIG.apiKey) {
        return {
          status: 'correct',
          apiKey: value,
          header: key,
        };
      }

      // Wrong API key
      return {
        status: 'wrong',
        apiKey: value,
        header: key,
      };
    }
  }

  // No API key found
  return { status: 'none' };
}

/**
 * Map vulnerability types to MITRE ATT&CK technique IDs
 */
function getTechniqueId(vulnerabilityType: string): string {
  // T1552: Unsecured Credentials - using credentials found in code/documentation
  // T1190: Exploit Public-Facing Application - attempting to access admin endpoints without auth
  // T1110: Brute Force - trying incorrect/random API keys

  if (vulnerabilityType === 'admin-page-access-correct-api-key') {
    return 'T1552'; // Unsecured Credentials - found the API key somewhere
  } else if (vulnerabilityType === 'admin-page-access-incorrect-api-key') {
    return 'T1110'; // Brute Force - trying random/incorrect keys
  } else {
    return 'T1190'; // Exploit Public-Facing Application - no authentication attempt
  }
}

/**
 * Generate a session ID from request headers
 */
function getSessionId(request: Request): string {
  // Use IP address and timestamp for session tracking
  const ip = request.headers.get('x-forwarded-for') ||
             request.headers.get('x-real-ip') ||
             'unknown';

  // Create a simple hash-like session ID
  const timestamp = Date.now();
  return `${ip.split(',')[0]}_${timestamp}`;
}

/**
 * Log honeypot trigger to Supabase database with fingerprint detection
 */
export async function logHoneypotTrigger(
  result: ApiKeyCheckResult,
  request: Request,
  route?: string
) {
  const url = new URL(request.url);

  // Perform fingerprint analysis
  const fingerprint = analyzeFingerprint(request);

  // Map the result status to specific vulnerability types
  const vulnerabilityType =
    result.status === 'none'
      ? 'admin-page-access-no-api-key'
      : result.status === 'correct'
      ? 'admin-page-access-correct-api-key'
      : 'admin-page-access-incorrect-api-key';

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
    // Fingerprint detection fields
    entity_type: fingerprint.entityType,
    fingerprint_confidence: fingerprint.confidence,
    fingerprint_signals: fingerprint.signals,
    user_agent: fingerprint.userAgent,
    request_headers: fingerprint.rawHeaders,
    request_method: request.method,
    request_path: route || url.pathname,
  };

  console.log('[Honeypot] Attempting to log to Supabase:', {
    ...payload,
    request_headers: '[REDACTED]', // Don't log full headers
  });
  console.log('[Honeypot] Fingerprint:', fingerprint.entityType, `(${fingerprint.confidence}% confidence)`);
  console.log('[Honeypot] Supabase URL configured:', !!process.env.SUPABASE_URL);
  console.log('[Honeypot] Supabase key configured:', !!process.env.SUPABASE_SERVICE_ROLE_KEY);

  try {
    const { data, error } = await supabase
      .from('vulnerability_logs')
      .insert(payload);

    if (error) {
      console.error('[Honeypot] Failed to log to Supabase:', error);
      console.error('[Honeypot] Error details:', JSON.stringify(error, null, 2));
    } else {
      console.log('[Honeypot] Successfully logged to Supabase:', data);
    }
  } catch (err) {
    console.error('[Honeypot] Exception while logging:', err);
  }
}

/**
 * Export fingerprint analysis for use in other modules
 */
export { analyzeFingerprint, type FingerprintResult } from './fingerprint';
