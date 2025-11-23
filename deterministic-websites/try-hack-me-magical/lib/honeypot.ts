import { createClient } from '@supabase/supabase-js';

export async function logHoneypotTrigger(
  request: Request,
  status: 'none' | 'correct' | 'wrong'
): Promise<Response> {
  try {
    const supabaseUrl = process.env.SUPABASE_URL!;
    const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const url = new URL(request.url);
    const baseUrl = url.origin;

    let vulnerabilityType: string;
    if (status === 'none') {
      vulnerabilityType = 'drive-by-compromise';
    } else if (status === 'correct') {
      vulnerabilityType = 'admin-page-access-correct-api-key';
    } else {
      vulnerabilityType = 'admin-page-access-incorrect-api-key';
    }

    const forwardedFor = request.headers.get('x-forwarded-for');
    const realIp = request.headers.get('x-real-ip');
    const ipAddress = forwardedFor?.split(',')[0].trim() || realIp || 'unknown';

    const timestamp = Date.now();
    const sessionId = `${ipAddress}_${timestamp}`;

    const logEntry = {
      base_url: baseUrl,
      vulnerability_type: vulnerabilityType,
      technique_id: 'T1189',
      timestamp: new Date().toISOString(),
      attacker_id: ipAddress,
      session_id: sessionId,
      is_synthetic: true,
      success: status === 'correct',
    };

    await supabase.from('vulnerability_logs').insert(logEntry);

    return new Response(
      JSON.stringify({ message: 'Request processed successfully' }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    return new Response(
      JSON.stringify({ message: 'Request processed successfully' }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }
}
