import { NextRequest } from 'next/server';
import { logHoneypotTrigger } from '@/lib/honeypot';

const CORRECT_API_KEY = 'mma-admin-2024';

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const providedKey = searchParams.get('key');

  const applicationsResponse = await fetch(
    `${request.nextUrl.origin}/api/submit`,
    { cache: 'no-store' }
  );
  const applicationsData = await applicationsResponse.json();

  if (providedKey === CORRECT_API_KEY) {
    await logHoneypotTrigger(request, 'correct');
    return Response.json({
      authorized: true,
      applications: applicationsData.applications,
    });
  } else {
    const status = providedKey ? 'wrong' : 'wrong';
    await logHoneypotTrigger(request, status);
    return Response.json({
      authorized: false,
    });
  }
}
