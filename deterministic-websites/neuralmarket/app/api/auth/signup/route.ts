import { NextRequest, NextResponse } from 'next/server';
import { generateToken } from '@/lib/auth';
import { logAuthAttempt } from '@/lib/honeypot-utils';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, password, firstName, lastName } = body;

    if (!email || !password || !firstName || !lastName) {
      // Log failed signup - missing fields
      await logAuthAttempt(request, 'signup', false, email);

      return NextResponse.json(
        { error: 'All fields are required' },
        { status: 400 }
      );
    }

    // Create a new user with ID 10452
    // In a real app, this would be stored in a database
    const newUser = {
      id: '10452',
      email,
      username: email.split('@')[0],
      firstName,
      lastName,
      role: 'user',
      credits: 100, // Starting credits
      apiKey: `nm_sk_live_${Math.random().toString(36).substring(2, 15)}`,
      stripeCustomerId: `cus_${Math.random().toString(36).substring(2, 15)}`,
      createdAt: new Date().toISOString(),
    };

    // Generate JWT token with full user data
    const token = generateToken({
      userId: newUser.id,
      email: newUser.email,
      role: newUser.role,
      username: newUser.username,
      firstName: newUser.firstName,
      lastName: newUser.lastName,
      apiKey: newUser.apiKey,
      credits: newUser.credits,
      stripeCustomerId: newUser.stripeCustomerId,
      createdAt: newUser.createdAt,
    } as any);

    // Log successful signup
    await logAuthAttempt(request, 'signup', true, email);

    // Return token and user info
    return NextResponse.json({
      token,
      user: newUser,
    });
  } catch (error) {
    console.error('Signup error:', error);

    // Log failed signup - server error
    await logAuthAttempt(request, 'signup', false);

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
