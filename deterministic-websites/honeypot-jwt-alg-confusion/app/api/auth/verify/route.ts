import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { logHoneypotTrigger } from '@/lib/supabase';

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
    let isAttackAttempt = false;

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
            isAttackAttempt = true;
            console.log('✅ HS256 verification succeeded!');
            console.log('✅ Decoded payload:', decoded);
          } else {
            console.log('❌ HS256 signature mismatch');
            throw new Error('Invalid signature');
          }
        } else {
          console.log('🔍 Attempting RS256 verification...');
          // Try RS256 verification for other algorithms
          decoded = jwt.verify(token, publicKey, {
            algorithms: ['RS256']
          });
          console.log('✅ RS256 verification succeeded');
        }
      } catch (err) {
        console.log('❌ Verification error:', err);
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
        return NextResponse.json(
          { error: 'Invalid token' },
          { status: 401 }
        );
      }
    }

    // Log successful attack if HS256 was used
    if (isAttackAttempt || algorithmUsed === 'HS256') {
      console.log('🚨 Logging attack to honeypot...');
      await logHoneypotTrigger({
        vulnerability_type: 'jwt_algorithm_confusion',
        base_url: process.env.VERCEL_PROJECT_PRODUCTION_URL ?? 'unknown',
      });
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