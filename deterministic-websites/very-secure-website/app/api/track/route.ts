import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { event, data, session_id, user_id, timestamp } = body;

    // Extract attacker IP
    const attackerId =
      request.headers.get('x-forwarded-for')?.split(',')[0] ||
      request.headers.get('x-real-ip') ||
      'unknown';

    // Determine base_url
    const url = new URL(request.url);
    const baseUrl = process.env.VERCEL_PROJECT_PRODUCTION_URL
      ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
      : url.origin;

    const payload = {
      base_url: baseUrl,
      event_type: event,
      event_data: data,
      session_id,
      user_id,
      attacker_id: attackerId,
      timestamp,
    };

    if (!supabase) {
      console.warn('[Tracking] Supabase not configured - skipping log');
      console.log('[Tracking] Would have logged:', payload);
      return NextResponse.json({ success: true });
    }

    const { error } = await supabase.from('events').insert(payload);

    if (error) {
      console.error('[Tracking] Failed to log to Supabase:', error);
      return NextResponse.json({ error: 'Failed to log event' }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('[Tracking] Error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
