import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';

// Mock user database
const USERS = {
  'user@example.com': { password: 'password123', role: 'user', userId: '1' },
  'admin@example.com': { password: 'admin123', role: 'admin', userId: '2' }
};

export async function POST(request: NextRequest) {
  try {
    const { email, password } = await request.json();

    // Simple authentication check
    const user = USERS[email as keyof typeof USERS];
    if (!user || user.password !== password) {
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Sign JWT with RS256 (secure algorithm)
    const token = jwt.sign(
      {
        sub: user.userId,
        email,
        role: user.role,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
      },
      process.env.JWT_PRIVATE_KEY!.replace(/\\n/g, '\n'),
      { algorithm: 'RS256' }
    );

    return NextResponse.json({ token });
  } catch (error) {
    return NextResponse.json(
      { error: 'Login failed' },
      { status: 500 }
    );
  }
}