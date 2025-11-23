import Link from 'next/link';
import { supabase } from '@/lib/supabase';
import { notFound } from 'next/navigation';

interface Attack {
  id: string;
  timestamp: string;
  base_url: string;
  vulnerability_type: string;
  technique_id: string;
  attacker_id: string;
  session_id: string;
  success: boolean;
  is_synthetic?: boolean;
  url_path?: string;
}

async function getAttackDetails(id: string) {
  // Get the specific attack
  const { data: attack, error } = await supabase
    .from('vulnerability_logs')
    .select('*')
    .eq('id', id)
    .single();

  if (error || !attack) {
    return null;
  }

  // Get session attacks
  const { data: sessionAttacks } = await supabase
    .from('vulnerability_logs')
    .select('*')
    .eq('session_id', attack.session_id)
    .order('timestamp', { ascending: false })
    .limit(50);

  // Get related attacks from same IP
  const { data: relatedAttacks } = await supabase
    .from('vulnerability_logs')
    .select('*')
    .eq('attacker_id', attack.attacker_id)
    .neq('id', id)
    .order('timestamp', { ascending: false })
    .limit(20);

  return {
    attack,
    sessionAttacks: sessionAttacks || [],
    relatedAttacks: relatedAttacks || []
  };
}

function formatTimestamp(timestamp: string) {
  const date = new Date(timestamp);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

function formatTimeShort(timestamp: string) {
  const date = new Date(timestamp);
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

export default async function AttackDetailsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const data = await getAttackDetails(id);

  if (!data) {
    notFound();
  }

  const { attack, sessionAttacks, relatedAttacks } = data;
  const fullUrl = attack.url_path ? `${attack.base_url}${attack.url_path}` : attack.base_url;

  return (
    <div className="min-h-screen relative bg-[#F5F5F7] dark:bg-charcoal">
      {/* Header */}
      <div className="border-b border-charcoal dark:border-cream bg-white dark:bg-charcoal">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
                ATTACK_DETAILS
              </h1>
              <div className="text-xs text-ghost">/system/attack/{attack.id.substring(0, 8)}</div>
            </div>
            <Link
              href="/dashboard"
              className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal text-charcoal dark:text-cream px-4 py-2 text-sm font-mono hover:bg-cyan hover:text-charcoal transition-colors"
            >
              [← BACK_TO_DASHBOARD]
            </Link>
          </div>
        </div>
      </div>

      <div className="px-6 py-6 space-y-6">
        {/* Main Attack Details */}
        <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
          <div className="mb-6">
            <h2 className="text-2xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
              PRIMARY_INFORMATION
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Left Column */}
            <div className="space-y-4">
              <div>
                <label className="text-xs text-ghost block mb-2">STATUS</label>
                <span
                  className={`px-3 py-1 text-sm font-mono font-bold ${
                    attack.success
                      ? 'bg-crimson text-cream'
                      : 'bg-amber text-charcoal'
                  }`}
                >
                  [{attack.success ? 'SUCCESS' : 'FAILED'}]
                </span>
              </div>

              <div>
                <label className="text-xs text-ghost block mb-2">TIMESTAMP</label>
                <div className="text-sm font-mono">{formatTimestamp(attack.timestamp)}</div>
              </div>

              <div>
                <label className="text-xs text-ghost block mb-2">ATTACK_ID</label>
                <div className="text-xs font-mono break-all text-ghost">{attack.id}</div>
              </div>

              <div>
                <label className="text-xs text-ghost block mb-2">SESSION_ID</label>
                <div className="text-xs font-mono break-all text-ghost">{attack.session_id}</div>
              </div>

              {attack.is_synthetic && (
                <div>
                  <label className="text-xs text-ghost block mb-2">TYPE</label>
                  <span className="px-3 py-1 bg-neural-purple text-cream text-sm font-mono font-bold">
                    [SYNTHETIC]
                  </span>
                </div>
              )}
            </div>

            {/* Right Column */}
            <div className="space-y-4">
              <div>
                <label className="text-xs text-ghost block mb-2">TARGET_URL</label>
                <div className="text-sm font-mono break-all">{fullUrl}</div>
              </div>

              <div>
                <label className="text-xs text-ghost block mb-2">BASE_URL</label>
                <div className="text-sm font-mono break-all text-cyan">{attack.base_url}</div>
              </div>

              {attack.url_path && (
                <div>
                  <label className="text-xs text-ghost block mb-2">URL_PATH</label>
                  <div className="text-sm font-mono break-all">{attack.url_path}</div>
                </div>
              )}

              <div>
                <label className="text-xs text-ghost block mb-2">VULNERABILITY_TYPE</label>
                <div className="text-sm font-mono">{attack.vulnerability_type}</div>
              </div>

              <div>
                <label className="text-xs text-ghost block mb-2">MITRE_TECHNIQUE</label>
                <div className="px-3 py-1 bg-charcoal dark:bg-cream text-cream dark:text-charcoal text-sm font-mono inline-block">
                  {attack.technique_id}
                </div>
              </div>

              <div>
                <label className="text-xs text-ghost block mb-2">SOURCE_IP</label>
                <div className="text-sm font-mono">{attack.attacker_id}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Session Timeline and Related Attacks Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Session Timeline */}
          {sessionAttacks.length > 1 && (
            <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
              <div className="mb-4 flex items-start justify-between gap-4">
                <div>
                  <h3 className="text-xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
                    SESSION_TIMELINE
                  </h3>
                  <div className="text-xs text-ghost">
                    {sessionAttacks.length} attacks in session
                  </div>
                </div>
                <Link
                  href={`/session/${attack.session_id}`}
                  className="border border-charcoal dark:border-cream bg-cyan text-charcoal px-3 py-2 text-xs font-mono hover:bg-amber transition-colors whitespace-nowrap"
                >
                  [VIEW_FULL_SESSION →]
                </Link>
              </div>
              <div className="space-y-2 max-h-[500px] overflow-y-auto">
                {sessionAttacks.map((a: Attack) => (
                  <Link
                    key={a.id}
                    href={`/attack/${a.id}`}
                    className={`block border-l-[3px] p-3 transition-colors ${
                      a.id === attack.id
                        ? 'border-cyan bg-cyan/10'
                        : a.success
                        ? 'border-crimson bg-crimson/5 hover:bg-crimson/10'
                        : 'border-amber bg-amber/5 hover:bg-amber/10'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <span
                        className={`px-2 py-0.5 text-[10px] font-mono font-bold ${
                          a.success
                            ? 'bg-crimson text-cream'
                            : 'bg-amber text-charcoal'
                        }`}
                      >
                        [{a.success ? 'SUCCESS' : 'FAILED'}]
                      </span>
                      <span className="text-[10px] text-ghost font-mono">
                        {formatTimeShort(a.timestamp)}
                      </span>
                    </div>
                    <div className="text-xs font-mono">{a.vulnerability_type}</div>
                    <div className="text-[10px] font-mono text-ghost mt-1">{a.technique_id}</div>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Related Attacks */}
          {relatedAttacks.length > 0 && (
            <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
              <div className="mb-4">
                <h3 className="text-xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
                  RELATED_ATTACKS
                </h3>
                <div className="text-xs text-ghost">
                  {relatedAttacks.length} attacks from IP {attack.attacker_id}
                </div>
              </div>
              <div className="space-y-2 max-h-[500px] overflow-y-auto">
                {relatedAttacks.map((a: Attack) => (
                  <Link
                    key={a.id}
                    href={`/attack/${a.id}`}
                    className={`block border-l-[3px] p-3 transition-colors ${
                      a.success
                        ? 'border-crimson bg-crimson/5 hover:bg-crimson/10'
                        : 'border-amber bg-amber/5 hover:bg-amber/10'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <span
                        className={`px-2 py-0.5 text-[10px] font-mono font-bold ${
                          a.success
                            ? 'bg-crimson text-cream'
                            : 'bg-amber text-charcoal'
                        }`}
                      >
                        [{a.success ? 'SUCCESS' : 'FAILED'}]
                      </span>
                      <span className="text-[10px] text-ghost font-mono">
                        {formatTimeShort(a.timestamp)}
                      </span>
                    </div>
                    <div className="text-xs font-mono break-all">{a.base_url}</div>
                    <div className="text-[10px] font-mono text-ghost mt-1">
                      {a.vulnerability_type} • {a.technique_id}
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
