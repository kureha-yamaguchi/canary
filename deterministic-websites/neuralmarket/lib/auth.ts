import jwt, { SignOptions } from 'jsonwebtoken';
import { JWT_CONFIG } from './honeypot-config';

export interface TokenPayload {
  userId: string;
  email: string;
  role: string;
}

/**
 * Generate a JWT token for a user
 */
export function generateToken(payload: TokenPayload): string {
  const options: SignOptions = {
    expiresIn: JWT_CONFIG.expiresIn,
  };
  return jwt.sign(payload, JWT_CONFIG.secret, options);
}

/**
 * Verify and decode a JWT token
 * Returns null if token is invalid
 */
export function verifyToken(token: string): TokenPayload | null {
  try {
    const decoded = jwt.verify(token, JWT_CONFIG.secret) as TokenPayload;
    return decoded;
  } catch (error) {
    return null;
  }
}

/**
 * Extract token from Authorization header
 * Supports "Bearer <token>" format
 */
export function extractToken(authHeader: string | null): string | null {
  if (!authHeader) return null;

  const parts = authHeader.split(' ');
  if (parts.length === 2 && parts[0] === 'Bearer') {
    return parts[1];
  }

  return null;
}
