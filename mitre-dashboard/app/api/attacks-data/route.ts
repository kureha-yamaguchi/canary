import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;

  // Parse filters
  const timeRange = parseInt(searchParams.get('timeRange') || '1440'); // Default 24 hours
  const includeSynthetic = searchParams.get('includeSynthetic') === 'true';
  const websites = searchParams.get('websites')?.split(',').filter(Boolean) || [];
  const vulnTypes = searchParams.get('vulnTypes')?.split(',').filter(Boolean) || [];
  const techniques = searchParams.get('techniques')?.split(',').filter(Boolean) || [];
  const ips = searchParams.get('ips')?.split(',').filter(Boolean) || [];

  try {
    // Calculate time threshold
    const timeThreshold = new Date(Date.now() - timeRange * 60000).toISOString();

    // Build query
    let query = supabase
      .from('vulnerability_logs')
      .select('*')
      .gte('timestamp', timeThreshold)
      .order('timestamp', { ascending: false });

    // Apply filters
    if (!includeSynthetic) {
      query = query.or('is_synthetic.is.null,is_synthetic.eq.false');
    }

    if (websites.length > 0) {
      query = query.in('base_url', websites);
    }

    if (vulnTypes.length > 0) {
      query = query.in('vulnerability_type', vulnTypes);
    }

    if (techniques.length > 0) {
      query = query.in('technique_id', techniques);
    }

    if (ips.length > 0) {
      query = query.in('attacker_id', ips);
    }

    const { data, error } = await query;

    if (error) {
      console.error('Error fetching attack data:', error);
      return NextResponse.json(
        { error: 'Failed to fetch attack data', details: error },
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
