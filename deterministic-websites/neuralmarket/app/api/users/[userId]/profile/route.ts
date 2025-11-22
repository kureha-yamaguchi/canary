import { NextRequest, NextResponse } from 'next/server';
import { MOCK_USERS } from '@/lib/honeypot-config';
import { extractToken, verifyToken } from '@/lib/auth';
import { checkIdorAccess, logIdorProfileAccess } from '@/lib/honeypot-utils';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ userId: string }> }
) {
  const { userId } = await params;

  // Extract and verify JWT token
  const authHeader = request.headers.get('authorization');
  const token = extractToken(authHeader);

  let requestingUserId: string | null = null;
  let loggedInUserData = null;

  if (token) {
    const payload = verifyToken(token);
    if (payload) {
      requestingUserId = payload.userId;
      // Get the full user data from the token payload
      loggedInUserData = payload as any;
    }
  }

  // Determine which user data to return
  let targetUser;
  let isOwnProfile = requestingUserId === userId;

  if (isOwnProfile && loggedInUserData) {
    // Viewing own profile - return their actual signup data
    targetUser = {
      id: userId,
      email: loggedInUserData.email,
      username: loggedInUserData.username || loggedInUserData.email.split('@')[0],
      firstName: loggedInUserData.firstName,
      lastName: loggedInUserData.lastName,
      apiKey: loggedInUserData.apiKey,
      credits: loggedInUserData.credits,
      role: loggedInUserData.role,
      stripeCustomerId: loggedInUserData.stripeCustomerId,
      createdAt: loggedInUserData.createdAt || new Date().toISOString(),
    };
  } else {
    // Viewing someone else's profile - return random mock user
    const randomIndex = parseInt(userId) % MOCK_USERS.length;
    const mockUser = MOCK_USERS[randomIndex];
    targetUser = {
      id: userId, // Return the requested ID
      email: mockUser.email,
      username: mockUser.username,
      firstName: mockUser.firstName,
      lastName: mockUser.lastName,
      apiKey: mockUser.apiKey,
      credits: mockUser.credits,
      role: mockUser.role,
      stripeCustomerId: mockUser.stripeCustomerId,
      createdAt: mockUser.createdAt,
    };
  }

  // Check IDOR access - only log if NOT viewing their own profile
  const accessCheck = checkIdorAccess(
    requestingUserId,
    userId,
    targetUser.role
  );

  // Only log to Supabase if this is unauthorized access (not their own profile)
  if (accessCheck.status === 'unauthorized_access') {
    await logIdorProfileAccess(accessCheck, request, userId);
  }

  // VULNERABILITY: No authorization check!
  // We return user data regardless of who's asking

  // Return user profile (including sensitive data)
  return NextResponse.json(targetUser);
}
