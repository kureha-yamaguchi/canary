import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';

export async function GET(request: Request) {
  const url = new URL(request.url);
  const limit = parseInt(url.searchParams.get('limit') || '100');
  const offset = parseInt(url.searchParams.get('offset') || '0');
  const entityType = url.searchParams.get('entity_type');

  try {
    // Build query
    let query = supabase
      .from('vulnerability_logs')
      .select('*')
      .order('timestamp', { ascending: false })
      .range(offset, offset + limit - 1);

    // Filter by entity type if provided
    if (entityType && entityType !== 'all') {
      query = query.eq('entity_type', entityType);
    }

    const { data: logs, error } = await query;

    if (error) {
      console.error('[Traffic API] Error fetching logs:', error);
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    // Get summary statistics
    const { data: stats, error: statsError } = await supabase
      .from('vulnerability_logs')
      .select('entity_type')
      .then(async (result) => {
        if (result.error) return { data: null, error: result.error };

        const allLogs = result.data || [];
        const summary = {
          total: allLogs.length,
          human: allLogs.filter(l => l.entity_type === 'human').length,
          automation: allLogs.filter(l => l.entity_type === 'automation').length,
          ai_agent: allLogs.filter(l => l.entity_type === 'ai_agent').length,
          unknown: allLogs.filter(l => l.entity_type === 'unknown').length,
        };

        return { data: summary, error: null };
      });

    if (statsError) {
      console.error('[Traffic API] Error fetching stats:', statsError);
    }

    return NextResponse.json({
      logs: logs || [],
      stats: stats || { total: 0, human: 0, automation: 0, ai_agent: 0, unknown: 0 },
      pagination: {
        limit,
        offset,
        hasMore: (logs?.length || 0) === limit,
      },
    });
  } catch (err) {
    console.error('[Traffic API] Exception:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
