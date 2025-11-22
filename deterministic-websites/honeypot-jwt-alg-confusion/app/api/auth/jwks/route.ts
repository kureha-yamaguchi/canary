import { NextResponse } from 'next/server';
import crypto from 'crypto';

export async function GET() {
  // Extract public key components for JWKS format
  const publicKey = process.env.JWT_PUBLIC_KEY!.replace(/\\n/g, '\n');

  // Parse the public key to get modulus and exponent
  const keyObject = crypto.createPublicKey(publicKey);
  const jwk = keyObject.export({ format: 'jwk' });

  return NextResponse.json({
    keys: [
      {
        kty: 'RSA',
        use: 'sig',
        kid: 'main-key',
        alg: 'RS256',
        n: jwk.n,
        e: jwk.e
      }
    ]
  });
}
