'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';

interface Attack {
  id: string;
  timestamp: string;
  base_url: string;
  vulnerability_type: string;
  technique_id: string;
  attacker_id: string;
  success: boolean;
  is_synthetic?: boolean;
  url_path?: string;
  session_id?: string;
}

interface LiveAttacksFeedProps {
  includeSynthetic: boolean;
}

export function LiveAttacksFeed({ includeSynthetic }: LiveAttacksFeedProps) {
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchAttacks = async () => {
    try {
      const response = await fetch(
        `/api/recent-attacks?limit=20&includeSynthetic=${includeSynthetic}`
      );
      if (response.ok) {
        const data = await response.json();
        setAttacks(data);
      }
    } catch (error) {
      console.error('Error fetching recent attacks:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAttacks();
    const interval = setInterval(fetchAttacks, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, [includeSynthetic]);

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const truncateUrl = (url: string, maxLength: number = 35) => {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength) + '...';
  };

  return (
    <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
      <div className="mb-4">
        <h2 className="text-xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
          LATEST_ATTACKS
        </h2>
        <div className="text-xs text-ghost">Real-time attack stream</div>
      </div>

      <div className="space-y-2 max-h-[400px] overflow-y-auto">
        {loading ? (
          <div className="text-center py-8 text-ghost text-xs">[LOADING...]</div>
        ) : attacks.length === 0 ? (
          <div className="text-center py-8 text-ghost text-xs">[NO_ATTACKS_YET]</div>
        ) : (
          attacks.map((attack) => (
            <Link
              key={attack.id}
              href={`/attack/${attack.id}`}
              className={`block border-l-[3px] p-3 transition-colors hover:bg-cyan/5 ${
                attack.success
                  ? 'border-crimson bg-crimson/5'
                  : 'border-amber bg-amber/5'
              }`}
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <span
                  className={`px-2 py-0.5 text-[10px] font-mono font-bold ${
                    attack.success
                      ? 'bg-crimson text-cream'
                      : 'bg-amber text-charcoal'
                  }`}
                >
                  {attack.success ? '[SUCCESS]' : '[FAILED]'}
                </span>
                <span className="text-[10px] text-ghost font-mono">
                  {formatTime(attack.timestamp)}
                </span>
              </div>

              <div className="space-y-1">
                <div className="text-xs font-mono text-charcoal dark:text-cream">
                  {truncateUrl(attack.base_url)}
                </div>

                <div className="flex items-center gap-2">
                  <span className="px-1.5 py-0.5 bg-charcoal dark:bg-cream text-cream dark:text-charcoal text-[10px] font-mono">
                    {attack.technique_id}
                  </span>
                  <span className="text-[10px] text-ghost font-mono">
                    {attack.vulnerability_type}
                  </span>
                </div>

                {attack.attacker_id && (
                  <div className="text-[10px] text-ghost font-mono">
                    IP: {attack.attacker_id}
                  </div>
                )}
              </div>
            </Link>
          ))
        )}
      </div>
    </div>
  );
}

