import { createClient } from '@supabase/supabase-js';

// Server-side only - no NEXT_PUBLIC prefix
// Use service role key for server-side operations that bypass RLS
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Only create client if env vars are set
export const supabase = supabaseUrl && supabaseServiceKey
  ? createClient(supabaseUrl, supabaseServiceKey)
  : null;

// Database types for vulnerability logging
export interface VulnerabilityLog {
  id?: string;
  base_url: string;
  vulnerability_type: string;
  technique_id: string;
  timestamp?: string;
  attacker_id: string;
  session_id: string;
  success?: boolean;
  url_path?: string;
  is_synthetic?: boolean;
}

/**
 * Log IDOR honeypot trigger to Supabase database
 */
export async function logIdorAttempt(payload: VulnerabilityLog) {
  if (!supabase) {
    console.warn('[Honeypot] Supabase not configured - skipping log. Set SUPABASE_URL and SUPABASE_SERVICE_KEY in .env.local');
    console.log('[Honeypot] Would have logged:', payload);
    return;
  }

  try {
    const { error } = await supabase
      .from('vulnerability_logs')
      .insert(payload);

    if (error) {
      console.error('[Honeypot] Failed to log to Supabase:', error);
    } else {
      console.log('[Honeypot] Successfully logged IDOR attempt');
    }
  } catch (err) {
    console.error('[Honeypot] Error logging IDOR attempt:', err);
  }
}
