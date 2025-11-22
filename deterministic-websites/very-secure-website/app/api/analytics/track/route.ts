import { NextRequest, NextResponse } from 'next/server';
import { logGranularEvent, GranularEvent } from '@/lib/analytics';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    
    // Extract IP from headers
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0] ||
               request.headers.get('x-real-ip') ||
               'unknown';
    
    // Extract user agent
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    const event: GranularEvent = {
      ...body,
      ip_address: ip,
      user_agent: userAgent,
    };
    
    await logGranularEvent(event);
    
    return NextResponse.json({ success: true }, { status: 200 });
  } catch (error) {
    console.error('Error tracking event:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to track event' },
      { status: 500 }
    );
  }
}