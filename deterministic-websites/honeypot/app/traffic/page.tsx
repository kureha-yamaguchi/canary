'use client';

import { useEffect, useState, useCallback } from 'react';

interface FingerprintSignal {
  name: string;
  value: string | boolean | number;
  weight: number;
  category: string;
}

interface TrafficLog {
  id: string;
  base_url: string;
  vulnerability_type: string;
  technique_id: string;
  timestamp: string;
  attacker_id: string;
  session_id: string;
  entity_type: 'human' | 'automation' | 'ai_agent' | 'unknown';
  fingerprint_confidence: number;
  fingerprint_signals: FingerprintSignal[];
  user_agent: string | null;
  request_method: string;
  request_path: string;
}

interface TrafficStats {
  total: number;
  human: number;
  automation: number;
  ai_agent: number;
  unknown: number;
}

interface TrafficResponse {
  logs: TrafficLog[];
  stats: TrafficStats;
  pagination: {
    limit: number;
    offset: number;
    hasMore: boolean;
  };
}

const ENTITY_COLORS = {
  human: { bg: 'bg-green-500', text: 'text-green-500', border: 'border-green-500' },
  automation: { bg: 'bg-yellow-500', text: 'text-yellow-500', border: 'border-yellow-500' },
  ai_agent: { bg: 'bg-purple-500', text: 'text-purple-500', border: 'border-purple-500' },
  unknown: { bg: 'bg-gray-500', text: 'text-gray-500', border: 'border-gray-500' },
};

const ENTITY_ICONS = {
  human: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
    </svg>
  ),
  automation: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  ),
  ai_agent: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
    </svg>
  ),
  unknown: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
};

function formatDate(timestamp: string) {
  return new Date(timestamp).toLocaleString();
}

function StatCard({
  title,
  value,
  entityType,
  onClick,
  isActive
}: {
  title: string;
  value: number;
  entityType: keyof typeof ENTITY_COLORS;
  onClick: () => void;
  isActive: boolean;
}) {
  const colors = ENTITY_COLORS[entityType];

  return (
    <button
      onClick={onClick}
      className={`p-4 rounded-lg border-2 transition-all ${
        isActive ? `${colors.border} bg-black/50` : 'border-white/10 bg-black/30'
      } hover:border-white/30`}
    >
      <div className="flex items-center gap-2 mb-2">
        <span className={colors.text}>{ENTITY_ICONS[entityType]}</span>
        <span className="text-sm text-white/60">{title}</span>
      </div>
      <div className={`text-3xl font-bold ${colors.text}`}>{value}</div>
    </button>
  );
}

function LogRow({ log, isExpanded, onToggle }: { log: TrafficLog; isExpanded: boolean; onToggle: () => void }) {
  const colors = ENTITY_COLORS[log.entity_type];

  return (
    <div className="border-b border-white/10">
      <button
        onClick={onToggle}
        className="w-full p-4 flex items-center gap-4 hover:bg-white/5 transition-colors text-left"
      >
        <div className={`${colors.bg} rounded-full p-2`}>
          {ENTITY_ICONS[log.entity_type]}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-sm font-medium ${colors.text}`}>
              {log.entity_type.replace('_', ' ').toUpperCase()}
            </span>
            <span className="text-xs text-white/40">
              {log.fingerprint_confidence}% confidence
            </span>
          </div>
          <div className="text-sm text-white/80 truncate">
            {log.request_method} {log.request_path}
          </div>
        </div>

        <div className="text-right">
          <div className="text-xs text-white/40">{formatDate(log.timestamp)}</div>
          <div className="text-xs text-white/60">{log.attacker_id}</div>
        </div>

        <svg
          className={`w-5 h-5 text-white/40 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {isExpanded && (
        <div className="px-4 pb-4 bg-black/20">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <h4 className="text-white/60 mb-2">Request Details</h4>
              <dl className="space-y-1">
                <div className="flex gap-2">
                  <dt className="text-white/40">Vulnerability:</dt>
                  <dd className="text-white/80">{log.vulnerability_type}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-white/40">Technique ID:</dt>
                  <dd className="text-white/80">{log.technique_id}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-white/40">Session:</dt>
                  <dd className="text-white/80 truncate">{log.session_id}</dd>
                </div>
              </dl>
            </div>

            <div>
              <h4 className="text-white/60 mb-2">User Agent</h4>
              <p className="text-xs text-white/60 break-all">
                {log.user_agent || 'No user agent'}
              </p>
            </div>
          </div>

          {log.fingerprint_signals && log.fingerprint_signals.length > 0 && (
            <div className="mt-4">
              <h4 className="text-white/60 mb-2">Detection Signals</h4>
              <div className="flex flex-wrap gap-2">
                {log.fingerprint_signals.map((signal, idx) => (
                  <span
                    key={idx}
                    className={`px-2 py-1 rounded text-xs ${
                      signal.weight > 0 ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                    }`}
                  >
                    {signal.name} ({signal.weight > 0 ? '+' : ''}{signal.weight})
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function TrafficDashboard() {
  const [data, setData] = useState<TrafficResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit: '50' });
      if (filter !== 'all') {
        params.set('entity_type', filter);
      }

      const res = await fetch(`/api/traffic?${params}`);
      if (!res.ok) throw new Error('Failed to fetch traffic data');

      const json = await res.json();
      setData(json);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchData]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 text-white">
      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold">Traffic Dashboard</h1>
            <p className="text-white/60 mt-1">
              Real-time fingerprint detection and traffic analysis
            </p>
          </div>

          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="rounded"
              />
              <span className="text-white/60">Auto-refresh</span>
            </label>

            <button
              onClick={fetchData}
              className="px-4 py-2 bg-white/10 hover:bg-white/20 rounded-lg transition-colors"
            >
              Refresh
            </button>

            <a
              href="/"
              className="px-4 py-2 bg-white/10 hover:bg-white/20 rounded-lg transition-colors"
            >
              Back to Site
            </a>
          </div>
        </div>

        {/* Stats Cards */}
        {data?.stats && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
            <StatCard
              title="Total Requests"
              value={data.stats.total}
              entityType="unknown"
              onClick={() => setFilter('all')}
              isActive={filter === 'all'}
            />
            <StatCard
              title="Humans"
              value={data.stats.human}
              entityType="human"
              onClick={() => setFilter('human')}
              isActive={filter === 'human'}
            />
            <StatCard
              title="Automation"
              value={data.stats.automation}
              entityType="automation"
              onClick={() => setFilter('automation')}
              isActive={filter === 'automation'}
            />
            <StatCard
              title="AI Agents"
              value={data.stats.ai_agent}
              entityType="ai_agent"
              onClick={() => setFilter('ai_agent')}
              isActive={filter === 'ai_agent'}
            />
            <StatCard
              title="Unknown"
              value={data.stats.unknown}
              entityType="unknown"
              onClick={() => setFilter('unknown')}
              isActive={filter === 'unknown'}
            />
          </div>
        )}

        {/* Entity Distribution Chart */}
        {data?.stats && data.stats.total > 0 && (
          <div className="mb-8 p-4 bg-black/30 rounded-lg border border-white/10">
            <h3 className="text-lg font-medium mb-4">Entity Distribution</h3>
            <div className="h-8 flex rounded-lg overflow-hidden">
              {data.stats.human > 0 && (
                <div
                  className="bg-green-500 flex items-center justify-center text-xs font-medium"
                  style={{ width: `${(data.stats.human / data.stats.total) * 100}%` }}
                >
                  {Math.round((data.stats.human / data.stats.total) * 100)}%
                </div>
              )}
              {data.stats.automation > 0 && (
                <div
                  className="bg-yellow-500 flex items-center justify-center text-xs font-medium text-black"
                  style={{ width: `${(data.stats.automation / data.stats.total) * 100}%` }}
                >
                  {Math.round((data.stats.automation / data.stats.total) * 100)}%
                </div>
              )}
              {data.stats.ai_agent > 0 && (
                <div
                  className="bg-purple-500 flex items-center justify-center text-xs font-medium"
                  style={{ width: `${(data.stats.ai_agent / data.stats.total) * 100}%` }}
                >
                  {Math.round((data.stats.ai_agent / data.stats.total) * 100)}%
                </div>
              )}
              {data.stats.unknown > 0 && (
                <div
                  className="bg-gray-500 flex items-center justify-center text-xs font-medium"
                  style={{ width: `${(data.stats.unknown / data.stats.total) * 100}%` }}
                >
                  {Math.round((data.stats.unknown / data.stats.total) * 100)}%
                </div>
              )}
            </div>
            <div className="flex gap-4 mt-2 text-xs text-white/60">
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 bg-green-500 rounded-full"></span> Human
              </span>
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 bg-yellow-500 rounded-full"></span> Automation
              </span>
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 bg-purple-500 rounded-full"></span> AI Agent
              </span>
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 bg-gray-500 rounded-full"></span> Unknown
              </span>
            </div>
          </div>
        )}

        {/* Traffic Logs */}
        <div className="bg-black/30 rounded-lg border border-white/10 overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-lg font-medium">
              Recent Traffic
              {filter !== 'all' && (
                <span className="text-sm font-normal text-white/60 ml-2">
                  (filtered by {filter.replace('_', ' ')})
                </span>
              )}
            </h3>
          </div>

          {loading && !data && (
            <div className="p-8 text-center text-white/60">
              Loading traffic data...
            </div>
          )}

          {error && (
            <div className="p-8 text-center text-red-400">
              Error: {error}
            </div>
          )}

          {data?.logs && data.logs.length === 0 && (
            <div className="p-8 text-center text-white/60">
              No traffic logs yet. Trigger the honeypot to see data.
            </div>
          )}

          {data?.logs && data.logs.length > 0 && (
            <div className="divide-y divide-white/10">
              {data.logs.map((log) => (
                <LogRow
                  key={log.id}
                  log={log}
                  isExpanded={expandedId === log.id}
                  onToggle={() => setExpandedId(expandedId === log.id ? null : log.id)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
