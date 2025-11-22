import { createClient } from '@supabase/supabase-js';

// Server-side only - no NEXT_PUBLIC prefix
// Use service role key for server-side operations that bypass RLS
const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

export const supabase = createClient(supabaseUrl, supabaseServiceKey);

// Database types for vulnerability logging
export interface VulnerabilityLog {
  id?: string;
  base_url: string;
  vulnerability_type: string;
  technique_id: string;
  timestamp?: string;
  attacker_id: string;
  session_id: string;
}

