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

async function getSessionAttacks(sessionId: string) {
  const { data: attacks, error } = await supabase
    .from('vulnerability_logs')
    .select('*')
    .eq('session_id', sessionId)
    .order('timestamp', { ascending: false });

  if (error || !attacks || attacks.length === 0) {
    return null;
  }

  return attacks;
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

export default async function SessionDetailsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const attacks = await getSessionAttacks(id);

  if (!attacks) {
    notFound();
  }

  const successfulAttacks = attacks.filter(a => a.success).length;
  const failedAttacks = attacks.length - successfulAttacks;
  const successRate = attacks.length > 0 ? ((successfulAttacks / attacks.length) * 100).toFixed(1) : '0.0';
  const uniqueTargets = [...new Set(attacks.map(a => a.base_url))].length;
  const uniqueTechniques = [...new Set(attacks.map(a => a.technique_id))].length;
  const firstAttack = attacks[attacks.length - 1];
  const lastAttack = attacks[0];

  return (
    <div className="min-h-screen relative bg-[#F5F5F7] dark:bg-charcoal">
      {/* Header */}
      <div className="border-b border-charcoal dark:border-cream bg-white dark:bg-charcoal">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
                SESSION_ANALYSIS
              </h1>
              <div className="text-xs text-ghost">/system/session/{id.substring(0, 8)}</div>
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
        {/* Session Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4">
            <div className="text-xs text-ghost mb-1">TOTAL_ATTACKS</div>
            <div className="text-3xl font-bold text-cyan">{attacks.length}</div>
          </div>
          <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4">
            <div className="text-xs text-ghost mb-1">SUCCESS_RATE</div>
            <div className="text-3xl font-bold text-amber">{successRate}%</div>
          </div>
          <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4">
            <div className="text-xs text-ghost mb-1">UNIQUE_TARGETS</div>
            <div className="text-3xl font-bold text-crimson">{uniqueTargets}</div>
          </div>
          <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4">
            <div className="text-xs text-ghost mb-1">TECHNIQUES</div>
            <div className="text-3xl font-bold text-neural-purple">{uniqueTechniques}</div>
          </div>
        </div>

        {/* Session Information */}
        <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
          <div className="mb-6">
            <h2 className="text-2xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
              SESSION_INFORMATION
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <label className="text-xs text-ghost block mb-2">SESSION_ID</label>
                <div className="text-xs font-mono break-all">{id}</div>
              </div>

              <div>
                <label className="text-xs text-ghost block mb-2">SOURCE_IP</label>
                <div className="text-sm font-mono">{firstAttack.attacker_id}</div>
              </div>

              <div>
                <label className="text-xs text-ghost block mb-2">ATTACK_BREAKDOWN</label>
                <div className="flex gap-4">
                  <div>
                    <span className="px-3 py-1 bg-crimson text-cream text-xs font-mono font-bold">
                      [SUCCESS: {successfulAttacks}]
                    </span>
                  </div>
                  <div>
                    <span className="px-3 py-1 bg-amber text-charcoal text-xs font-mono font-bold">
                      [FAILED: {failedAttacks}]
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-xs text-ghost block mb-2">FIRST_ATTACK</label>
                <div className="text-sm font-mono">{formatTimestamp(firstAttack.timestamp)}</div>
              </div>

              <div>
                <label className="text-xs text-ghost block mb-2">LAST_ATTACK</label>
                <div className="text-sm font-mono">{formatTimestamp(lastAttack.timestamp)}</div>
              </div>

              <div>
                <label className="text-xs text-ghost block mb-2">DURATION</label>
                <div className="text-sm font-mono">
                  {Math.ceil((new Date(lastAttack.timestamp).getTime() - new Date(firstAttack.timestamp).getTime()) / 1000)} seconds
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Attack Timeline */}
        <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
          <div className="mb-4">
            <h2 className="text-2xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
              ATTACK_TIMELINE
            </h2>
            <div className="text-xs text-ghost">Chronological attack sequence</div>
          </div>

          <div className="space-y-2">
            {attacks.map((attack: Attack, index: number) => (
              <Link
                key={attack.id}
                href={`/attack/${attack.id}`}
                className={`block border-l-[3px] p-4 transition-colors ${
                  attack.success
                    ? 'border-crimson bg-crimson/5 hover:bg-crimson/10'
                    : 'border-amber bg-amber/5 hover:bg-amber/10'
                }`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 space-y-2">
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-ghost font-mono">#{attacks.length - index}</span>
                      <span
                        className={`px-2 py-0.5 text-[10px] font-mono font-bold ${
                          attack.success
                            ? 'bg-crimson text-cream'
                            : 'bg-amber text-charcoal'
                        }`}
                      >
                        [{attack.success ? 'SUCCESS' : 'FAILED'}]
                      </span>
                      <span className="text-xs text-ghost font-mono">
                        {formatTimeShort(attack.timestamp)}
                      </span>
                    </div>

                    <div className="text-sm font-mono break-all">
                      {attack.url_path ? `${attack.base_url}${attack.url_path}` : attack.base_url}
                    </div>

                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="px-2 py-0.5 bg-charcoal dark:bg-cream text-cream dark:text-charcoal text-[10px] font-mono">
                        {attack.technique_id}
                      </span>
                      <span className="text-xs text-ghost font-mono">
                        {attack.vulnerability_type}
                      </span>
                      {attack.is_synthetic && (
                        <span className="px-2 py-0.5 bg-neural-purple text-cream text-[10px] font-mono">
                          [SYNTHETIC]
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="text-xs text-cyan font-mono whitespace-nowrap">
                    [VIEW_DETAILS →]
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
