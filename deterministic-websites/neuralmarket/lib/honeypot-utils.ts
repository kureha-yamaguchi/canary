import { logIdorAttempt, VulnerabilityLog } from './supabase';

export type IdorCheckResult =
  | { status: 'own_profile'; userId: string }
  | { status: 'unauthorized_access'; requestingUserId: string; targetUserId: string; isAdmin: boolean }
  | { status: 'unauthenticated' };

/**
 * Check if a user is accessing their own profile or someone else's
 */
export function checkIdorAccess(
  requestingUserId: string | null,
  targetUserId: string,
  targetUserRole?: string
): IdorCheckResult {
  if (!requestingUserId) {
    return { status: 'unauthenticated' };
  }

  if (requestingUserId === targetUserId) {
    return { status: 'own_profile', userId: targetUserId };
  }

  return {
    status: 'unauthorized_access',
    requestingUserId,
    targetUserId,
    isAdmin: targetUserRole === 'admin',
  };
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
 * Map IDOR access type to vulnerability type
 */
function getVulnerabilityType(result: IdorCheckResult): string {
  if (result.status === 'own_profile') {
    return 'idor-own-profile-access';
  }

  if (result.status === 'unauthorized_access') {
    if (result.isAdmin) {
      return 'idor-admin-profile-access';
    }
    return 'idor-unauthorized-profile-access';
  }

  return 'idor-unauthenticated-access';
}

/**
 * Log IDOR attempt to Supabase database
 *
 * MITRE ATT&CK Technique Mapping:
 * - T1087: Account Discovery - Adversaries enumerate user accounts
 */
export async function logIdorProfileAccess(
  result: IdorCheckResult,
  request: Request,
  targetUserId: string
) {
  const url = new URL(request.url);

  // Extract attacker_id (IP address)
  const attackerId =
    request.headers.get('x-forwarded-for')?.split(',')[0] ||
    request.headers.get('x-real-ip') ||
    'unknown';

  // Generate session ID for tracking
  const sessionId = getSessionId(request);

  // Determine base_url (use production URL or localhost)
  const baseUrl = process.env.VERCEL_PROJECT_PRODUCTION_URL
    ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
    : url.origin;

  // Map to vulnerability type
  const vulnerabilityType = getVulnerabilityType(result);

  // T1087: Account Discovery
  const techniqueId = 'T1087';

  // Determine if this was a successful unauthorized access
  const success = result.status === 'unauthorized_access';

  const payload = {
    base_url: baseUrl,
    vulnerability_type: vulnerabilityType,
    technique_id: techniqueId,
    attacker_id: attackerId,
    session_id: sessionId,
    success,
    url_path: url.pathname,
  };

  console.log('[Honeypot] IDOR attempt detected:', {
    status: result.status,
    targetUserId,
    vulnerabilityType,
  });

  await logIdorAttempt(payload);
}

/**
 * Log authentication attempt to Supabase
 *
 * MITRE ATT&CK Technique Mappings:
 * - T1078: Valid Accounts - Using legitimate credentials
 * - T1110: Brute Force - Password guessing/credential stuffing
 */
export async function logAuthAttempt(
  request: Request,
  type: 'signup' | 'login',
  success: boolean,
  email?: string
) {
  const url = new URL(request.url);

  // Extract attacker_id (IP address)
  const attackerId =
    request.headers.get('x-forwarded-for')?.split(',')[0] ||
    request.headers.get('x-real-ip') ||
    'unknown';

  // Generate session ID for tracking
  const sessionId = getSessionId(request);

  // Determine base_url (use production URL or localhost)
  const baseUrl = process.env.VERCEL_PROJECT_PRODUCTION_URL
    ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
    : url.origin;

  // Map to vulnerability type and technique
  let vulnerabilityType: string;
  let techniqueId: string;

  if (type === 'signup') {
    vulnerabilityType = success ? 'auth-signup-success' : 'auth-signup-failed';
    techniqueId = 'T1078'; // Valid Accounts
  } else {
    vulnerabilityType = success ? 'auth-login-success' : 'auth-login-failed';
    techniqueId = success ? 'T1078' : 'T1110'; // Valid Accounts vs Brute Force
  }

  const payload: VulnerabilityLog = {
    base_url: baseUrl,
    vulnerability_type: vulnerabilityType,
    technique_id: techniqueId,
    attacker_id: attackerId,
    session_id: sessionId,
    success,
    url_path: url.pathname,
  };

  console.log('[Honeypot] Auth attempt:', {
    type,
    success,
    email: email || 'N/A',
    vulnerabilityType,
  });

  await logIdorAttempt(payload);
}
