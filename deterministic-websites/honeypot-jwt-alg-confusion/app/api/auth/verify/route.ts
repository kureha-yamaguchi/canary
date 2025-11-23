import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { logHoneypotTrigger } from '@/lib/supabase';

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

const TECHNIQUE_APPLICATION_ACCESS_TOKEN = 'T1550';
const TECHNIQUE_BRUTE_FORCE = 'T1110';

async function logAttempt(
  request: Request,
  success?: boolean,
  technique_id: string = TECHNIQUE_BRUTE_FORCE, // Default to: Application Access Token
) {
  const vulnerability_type = technique_id === TECHNIQUE_APPLICATION_ACCESS_TOKEN
    ? 'brute-force'
    : 'jwt-algorithm-confusion';
  const attacker_id = request.headers.get('x-forwarded-for')?.split(',')[0] ||
    request.headers.get('x-real-ip') ||
    'unknown';
  const session_id = getSessionId(request);
  console.log("logging attempt to supabase");
  const base_url = (new URL(request.url)).origin;
  await logHoneypotTrigger({
      vulnerability_type,
      base_url,
      technique_id,
      attacker_id,
      session_id,
      success,
    });
}

// 🔥 TOGGLE VULNERABILITY HERE 🔥
const VULNERABLE_MODE = true; // Set to false for secure mode

export async function POST(request: NextRequest) {
  try {
    const { token } = await request.json();

    if (!token) {
      return NextResponse.json({ error: 'No token provided' }, { status: 400 });
    }

    // Decode header to check algorithm (without verification)
    const decodedHeader = jwt.decode(token, { complete: true });
    const algorithmUsed = decodedHeader?.header?.alg;

    const publicKey = process.env.JWT_PUBLIC_KEY!.replace(/\\n/g, '\n');

    let decoded;

    if (VULNERABLE_MODE) {
      // ⚠️ VULNERABLE: Accepts any algorithm
      try {
        if (algorithmUsed === 'HS256') {
          // Manually verify HS256 using public key as HMAC secret
          // This simulates the algorithm confusion vulnerability
          const [headerB64, payloadB64, signatureB64] = token.split('.');

          const message = `${headerB64}.${payloadB64}`;
          const expectedSignature = crypto
            .createHmac('sha256', publicKey)
            .update(message)
            .digest('base64url');

          if (signatureB64 === expectedSignature) {
            const payloadStr = Buffer.from(payloadB64, 'base64url').toString();
            decoded = JSON.parse(payloadStr);
            console.log('✅ HS256 verification succeeded!');
            console.log('✅ Decoded payload:', decoded);
          } else {
            console.log('❌ HS256 signature mismatch');
            throw new Error('Invalid signature');
          }
        } else {
          console.log('🔍 Attempting RS256 verification...');
          // Try RS256 verification for other algorithms
          // This would be a legitimate login, so don't log as an attempt
          decoded = jwt.verify(token, publicKey, {
            algorithms: ['RS256']
          });
          console.log('✅ RS256 verification succeeded');
        }
      } catch (err) {
        console.log('❌ Verification error:', err);
        // Not using the HS256 vulnerability, so list it as brute force T1110
        await logAttempt(request, false, TECHNIQUE_APPLICATION_ACCESS_TOKEN)
        return NextResponse.json(
          { error: 'Invalid token' },
          { status: 401 }
        );
      }
    } else {
      // ✅ SECURE: Only accepts RS256
      try {
        decoded = jwt.verify(token, publicKey, {
          algorithms: ['RS256'] // Whitelist only secure algorithm
        });
      } catch {
        await logAttempt(request, false)
        return NextResponse.json(
          { error: 'Invalid token' },
          { status: 401 }
        );
      }
    }

    if (algorithmUsed === 'HS256') {
      // If they got here and the alg was HS256, it was a success
      await logAttempt(request, true);
    } else {
      // Unlikely, but if they guesses credentials, mark it as brute force success
      await logAttempt(request, true, TECHNIQUE_BRUTE_FORCE)
    }

    return NextResponse.json({
      valid: true,
      decoded,
    });

  } catch (err) {
    console.log('❌ Top-level error:', err);
    return NextResponse.json(
      { error: 'Verification failed' },
      { status: 500 }
    );
  }
}