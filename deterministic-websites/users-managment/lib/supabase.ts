import { createClient, SupabaseClient } from '@supabase/supabase-js';

// Server-side only - no NEXT_PUBLIC prefix
// Use service role key for server-side operations that bypass RLS
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Only create Supabase client if environment variables are configured
export const supabase: SupabaseClient | null = 
  supabaseUrl && supabaseServiceKey
    ? createClient(supabaseUrl, supabaseServiceKey)
    : null;

// Database types for vulnerability logging
export interface VulnerabilityLog {
  id?: string;
  base_url: string;
  path?: string;
  vulnerability_type: string;
  technique_id: string;
  timestamp?: string;
  attacker_id: string;
  session_id: string;
}

