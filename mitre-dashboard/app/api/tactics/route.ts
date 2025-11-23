import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';

export async function GET() {
  try {
    // Get all tactics with their techniques
    const { data: tacticsData, error: tacticsError } = await supabase
      .from('tactics')
      .select('technique_id, tactic');

    if (tacticsError) {
      console.error('Error fetching tactics:', tacticsError);
      return NextResponse.json(
        { error: 'Failed to fetch tactics', details: tacticsError },
        { status: 500 }
      );
    }

    // Get all techniques
    const { data: techniquesData, error: techniquesError } = await supabase
      .from('techniques')
      .select('technique_id, name, description, url, domain');

    if (techniquesError) {
      console.error('Error fetching techniques:', techniquesError);
      return NextResponse.json(
        { error: 'Failed to fetch techniques', details: techniquesError },
        { status: 500 }
      );
    }

    // Create a map of technique_id to technique details
    const techniquesMap = new Map(
      techniquesData?.map(tech => [tech.technique_id, tech]) || []
    );

    // Group by tactic
    const tacticGroups: Record<string, any[]> = {};

    tacticsData?.forEach(row => {
      const technique = techniquesMap.get(row.technique_id);
      if (technique) {
        if (!tacticGroups[row.tactic]) {
          tacticGroups[row.tactic] = [];
        }
        tacticGroups[row.tactic].push({
          ...technique,
          tactic: row.tactic
        });
      }
    });

    return NextResponse.json({
      tactics: tacticGroups,
      techniques: techniquesData || []
    });
  } catch (error) {
    console.error('API error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
