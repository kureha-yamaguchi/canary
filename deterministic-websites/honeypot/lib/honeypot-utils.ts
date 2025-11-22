import { HONEYPOT_CONFIG } from './honeypot-config';

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
 * Log honeypot trigger to console with details
 */
export function logHoneypotTrigger(
  result: ApiKeyCheckResult,
  request: Request,
  route?: string
) {
  const url = new URL(request.url);
  const path = route || url.pathname;

  const level =
    result.status === 'none'
      ? 'no-api-key'
      : result.status === 'correct'
      ? 'api-key-correct'
      : 'api-key-wrong';

  const logObject = {
    level,
    route: path,
  };

  console.log(logObject);
}
