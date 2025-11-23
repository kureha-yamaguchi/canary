import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;

  // Parse query parameters
  const timeRange = parseInt(searchParams.get('timeRange') || '1440');
  const bucketMinutes = parseInt(searchParams.get('bucketMinutes') || '60');
  const includeSynthetic = searchParams.get('includeSynthetic') === 'true';
  const websites = searchParams.get('websites')?.split(',').filter(Boolean) || null;
  const vulnTypes = searchParams.get('vulnTypes')?.split(',').filter(Boolean) || null;
  const techniques = searchParams.get('techniques')?.split(',').filter(Boolean) || null;
  const ips = searchParams.get('ips')?.split(',').filter(Boolean) || null;

  try {
    // Call database functions for aggregated data
    const [histogramResult, statsResult, filtersResult] = await Promise.all([
      // Get histogram data (aggregated by time and tactic)
      supabase.rpc('get_attack_histogram', {
        time_range_minutes: timeRange,
        bucket_minutes: bucketMinutes,
        include_synthetic: includeSynthetic,
        filter_websites: websites,
        filter_vuln_types: vulnTypes,
        filter_techniques: techniques,
        filter_ips: ips
      }),

      // Get summary stats
      supabase.rpc('get_attack_stats', {
        time_range_minutes: timeRange,
        include_synthetic: includeSynthetic,
        filter_websites: websites,
        filter_vuln_types: vulnTypes,
        filter_techniques: techniques,
        filter_ips: ips
      }),

      // Get filter options
      supabase.rpc('get_filter_options', {
        time_range_minutes: timeRange,
        include_synthetic: includeSynthetic
      })
    ]);

    if (histogramResult.error) {
      console.error('Histogram error:', histogramResult.error);
      return NextResponse.json(
        { error: 'Failed to fetch histogram', details: histogramResult.error },
        { status: 500 }
      );
    }

    if (statsResult.error) {
      console.error('Stats error:', statsResult.error);
      return NextResponse.json(
        { error: 'Failed to fetch stats', details: statsResult.error },
        { status: 500 }
      );
    }

    if (filtersResult.error) {
      console.error('Filters error:', filtersResult.error);
      return NextResponse.json(
        { error: 'Failed to fetch filters', details: filtersResult.error },
        { status: 500 }
      );
    }

    return NextResponse.json({
      histogram: histogramResult.data || [],
      stats: statsResult.data || {},
      filters: filtersResult.data || {}
    });
  } catch (error) {
    console.error('API error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
