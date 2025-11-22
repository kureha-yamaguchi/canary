import { NextResponse } from 'next/server';
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

async function logAttempt(
  request: Request,
  path: string,
  success?: boolean,
  technique_id: string = TECHNIQUE_ACTIVE_SCANNING,
) {
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

// Catch-all route for any /* requests
export async function GET(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  const { slug } = await params;

  logAttempt(request, slug.join('/'));

  return NextResponse.json(
    { success: true },
    { status: 200 }
  );
}

export async function POST(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleGenericRequest(request, params);
}

// Also handle PUT, PATCH, DELETE
export async function PUT(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleGenericRequest(request, params);
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleGenericRequest(request, params);
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleGenericRequest(request, params);
}

async function handleGenericRequest(
  request: Request,
  params: Promise<{ slug: string[] }>,
) {
  const { slug } = await params;

  logAttempt(request, slug.join('/'));

  return NextResponse.json(
    { success: true },
    { status: 200 }
  );
}
