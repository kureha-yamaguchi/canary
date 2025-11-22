import { NextRequest, NextResponse } from 'next/server';
import { findUserByEmail } from '@/lib/honeypot-config';
import { generateToken } from '@/lib/auth';
import { logAuthAttempt } from '@/lib/honeypot-utils';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, password } = body;

    if (!email || !password) {
      // Log failed login - missing credentials
      await logAuthAttempt(request, 'login', false, email);

      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      );
    }

    // Find user by email
    const user = findUserByEmail(email);

    if (!user) {
      // Log failed login - user not found
      await logAuthAttempt(request, 'login', false, email);

      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // In a real app, we'd use bcrypt.compare()
    // For honeypot demo, simple string comparison
    if (user.password !== password) {
      // Log failed login - wrong password (brute force attempt)
      await logAuthAttempt(request, 'login', false, email);

      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Generate JWT token
    const token = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    // Log successful login
    await logAuthAttempt(request, 'login', true, email);

    // Return token and user info (excluding password)
    return NextResponse.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        credits: user.credits,
      },
    });
  } catch (error) {
    console.error('Login error:', error);

    // Log failed login - server error
    await logAuthAttempt(request, 'login', false);

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
