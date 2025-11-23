import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const limit = parseInt(searchParams.get('limit') || '50');
  const includeSynthetic = searchParams.get('includeSynthetic') === 'true';

  try {
    let query = supabase
      .from('vulnerability_logs')
      .select('id, timestamp, base_url, vulnerability_type, technique_id, attacker_id, success, is_synthetic, url_path, session_id')
      .order('timestamp', { ascending: false })
      .limit(limit);

    // Filter out synthetic data unless explicitly included
    if (!includeSynthetic) {
      query = query.or('is_synthetic.is.null,is_synthetic.eq.false');
    }

    const { data, error } = await query;

    if (error) {
      console.error('Error fetching recent attacks:', error);
      return NextResponse.json(
        { error: 'Failed to fetch recent attacks', details: error },
        { status: 500 }
      );
    }

    return NextResponse.json(data || []);
  } catch (error) {
    console.error('API error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

