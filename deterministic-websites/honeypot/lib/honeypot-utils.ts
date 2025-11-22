import { HONEYPOT_CONFIG } from './honeypot-config';
import { supabase } from './supabase';

export type ApiKeyCheckResult =
  | { status: 'correct'; apiKey: string; header: string }
  | { status: 'wrong'; apiKey: string; header: string }
  | { status: 'none' };

/**
 * Check if request headers contain an API key and validate it
 * Returns the status (correct, wrong, or none) along with key details
 */
export function checkApiKey(headers: Headers): ApiKeyCheckResult {
  // Check all headers for any API key
  for (const [key, value] of headers.entries()) {
    if (value.includes('sk_') || key.toLowerCase().includes('api')) {
      // Check if it's the correct API key
      if (value === HONEYPOT_CONFIG.apiKey) {
        return {
          status: 'correct',
          apiKey: value,
          header: key,
        };
      }

      // Wrong API key
      return {
        status: 'wrong',
        apiKey: value,
        header: key,
      };
    }
  }

  // No API key found
  return { status: 'none' };
}

/**
 * Log honeypot trigger to Supabase database
 */
export async function logHoneypotTrigger(
  result: ApiKeyCheckResult,
  request: Request,
  route?: string
) {
  const url = new URL(request.url);
  const path = route || url.pathname;

  // Map the result status to specific vulnerability types
  const vulnerabilityType =
    result.status === 'none'
      ? 'admin-page-access-no-api-key'
      : result.status === 'correct'
      ? 'admin-page-access-correct-api-key'
      : 'admin-page-access-incorrect-api-key';

  // Extract attack_id (IP address or other identifier)
  const attackId =
    request.headers.get('x-forwarded-for') ||
    request.headers.get('x-real-ip') ||
    'unknown';

  try {
    const { error } = await supabase
      .from('vulnerability_logs')
      .insert({
        base_url: url.origin,
        path: path,
        vulnerability_type: vulnerabilityType,
        attack_id: attackId,
      });

    if (error) {
      console.error('Failed to log to Supabase:', error);
    }
  } catch (err) {
    console.error('Error logging honeypot trigger:', err);
  }
}
