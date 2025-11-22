import { supabase } from '@/lib/supabase';

export interface GranularEvent {
  session_id: string;
  event_type: string;
  event_category: string;
  element_id?: string;
  element_class?: string;
  element_text?: string;
  page_url: string;
  page_path: string;
  scroll_depth?: number;
  click_x?: number;
  click_y?: number;
  viewport_width?: number;
  viewport_height?: number;
  user_agent?: string;
  ip_address?: string;
  metadata?: Record<string, any>;
}

/**
 * Log a granular event to Supabase
 */
export async function logGranularEvent(event: GranularEvent) {
  try {
    const { error } = await supabase
      .from('granular_events')
      .insert(event);

    if (error) {
      console.error('Failed to log granular event:', error);
    }
  } catch (err) {
    console.error('Error logging granular event:', err);
  }
}