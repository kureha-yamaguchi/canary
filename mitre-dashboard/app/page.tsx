import Link from 'next/link';
import { supabase } from '@/lib/supabase';

async function getStats() {
  const now = new Date();
  const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  // Get all attacks in last 24h
  const { data: attacks, error } = await supabase
    .from('vulnerability_logs')
    .select('success')
    .gte('timestamp', twentyFourHoursAgo.toISOString())
    .order('timestamp', { ascending: false });

  if (error) {
    console.error('Error fetching stats:', error);
    return { attacks24h: 0, successRate: 0 };
  }

  const attacks24h = attacks?.length || 0;
  const successfulAttacks = attacks?.filter(a => a.success === true).length || 0;
  const successRate = attacks24h > 0 ? (successfulAttacks / attacks24h) * 100 : 0;

  return { attacks24h, successRate };
}

export default async function Home() {
  const { attacks24h, successRate } = await getStats();

  return (
    <div className="min-h-screen relative noise-bg">
      {/* Status Bar */}
      <div className="fixed top-0 left-0 right-0 border-b-[3px] border-charcoal dark:border-cream bg-cream dark:bg-charcoal z-50">
        <div className="px-6 py-3 flex items-center justify-between font-mono text-xs tracking-wider">
          <div className="flex gap-6">
            <span className="text-cyan flex items-center gap-2">
              <span className="w-2 h-2 bg-cyan pulse-dot"></span>
              [SYSTEM: ACTIVE]
            </span>
          </div>
          <div className="flex gap-4">
            <span className="text-ghost">[FRAMEWORK: MITRE_ATT&CK]</span>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <main className="pt-16 px-6 max-w-5xl mx-auto min-h-screen flex items-center">
        <div className="w-full py-8">
          {/* Header */}
          <div className="mb-12">
            <h1 className="text-6xl md:text-8xl font-bold tracking-tighter mb-6 font-[family-name:var(--font-ibm-plex-mono)]">
              CANARY
            </h1>
            <p className="text-xl text-ghost font-mono max-w-2xl">
              Real-time AI threat intelligence and attack monitoring using the MITRE ATT&CK framework.
            </p>
          </div>

          {/* Two Main Boxes */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Live Dashboard */}
            <Link href="/dashboard">
              <div className="border-[3px] border-charcoal dark:border-cream p-6 hover:border-cyan hover:bg-cyan/5 transition-all cursor-pointer group min-h-80 flex flex-col justify-between">
                <div>
                  <div className="text-cyan text-4xl mb-3 font-mono">[01]</div>
                  <h2 className="text-2xl font-bold mb-2 group-hover:text-cyan transition-colors font-[family-name:var(--font-ibm-plex-mono)]">
                    LIVE_DASHBOARD
                  </h2>
                  <p className="text-ghost text-xs mb-4">
                    Monitor attacks in real-time, view statistics, and analyze threat patterns.
                  </p>
                  <div className="grid grid-cols-2 gap-3 mb-4">
                    <div className="border-[2px] border-charcoal dark:border-cream p-3">
                      <div className="text-xs text-ghost mb-1">24H_ATTACKS</div>
                      <div className="text-2xl font-bold text-amber">{attacks24h.toLocaleString()}</div>
                    </div>
                    <div className="border-[2px] border-charcoal dark:border-cream p-3">
                      <div className="text-xs text-ghost mb-1">SUCCESS_RATE</div>
                      <div className="text-2xl font-bold text-cyan">{successRate.toFixed(1)}%</div>
                    </div>
                  </div>
                </div>
                <div className="text-xs text-ghost group-hover:text-cyan transition-colors">
                  [&gt; ENTER_DASHBOARD]
                </div>
              </div>
            </Link>

            {/* MITRE Matrix */}
            <Link href="/matrix">
              <div className="border-[3px] border-charcoal dark:border-cream p-6 hover:border-cyan hover:bg-cyan/5 transition-all cursor-pointer group min-h-80 flex flex-col justify-between">
                <div>
                  <div className="text-cyan text-4xl mb-3 font-mono">[02]</div>
                  <h2 className="text-2xl font-bold mb-2 group-hover:text-cyan transition-colors font-[family-name:var(--font-ibm-plex-mono)]">
                    MITRE_MATRIX
                  </h2>
                  <p className="text-ghost text-xs mb-4">
                    Explore attack techniques mapped to the MITRE ATT&CK framework.
                  </p>
                </div>
                <div className="text-xs text-ghost group-hover:text-cyan transition-colors">
                  [&gt; VIEW_MATRIX]
                </div>
              </div>
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
}
