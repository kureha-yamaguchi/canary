import { NextRequest, NextResponse } from 'next/server';
import { logHoneypotTrigger } from '@/lib/supabase';
import { getVulnerabilityFromPath } from '@/lib/vulnerability-map';

const TECHNIQUE_ACTIVE_SCANNING = 'T1595';

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

async function logActiveScanningAttempt(
  request: Request,
  path: string,
  success?: boolean,
  technique_id: string = TECHNIQUE_ACTIVE_SCANNING,
) {
  console.log("logging attempt to supabase");
  const vulnerability_type = getVulnerabilityFromPath(path);
  const attacker_id = request.headers.get('x-forwarded-for')?.split(',')[0] ||
    request.headers.get('x-real-ip') ||
    'unknown';
  const session_id = getSessionId(request);
  console.log("logging attempt to supabase");
  const base_url = process.env.VERCEL_PROJECT_PRODUCTION_URL
    ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
    : 'http://localhost:3000'
  await logHoneypotTrigger({
      vulnerability_type,
      base_url,
      technique_id,
      attacker_id,
      session_id,
      success,
      url_path: `${request.method} ${path}`,
    });
}

export function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;
  logActiveScanningAttempt(request, path);
  // Let the request continue normally
  return NextResponse.next();
}

// Optional: configure which routes middleware runs on
export const config = {
  matcher: [
    /*
     * Match all request paths except static files and images, or the root (we require at least 1 character after)
     */
    '/((?!_next/static|_next/image|favicon.ico).+)',
  ],
};
