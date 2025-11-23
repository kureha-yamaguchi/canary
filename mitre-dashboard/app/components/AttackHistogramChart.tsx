'use client';

import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

interface HistogramDataPoint {
  time_bucket: string;
  tactic: string;
  tactic_name: string;
  attack_count: number;
}

interface TacticChartData {
  time: string;
  [key: string]: number | string;
}

interface AttackHistogramChartProps {
  histogramData: HistogramDataPoint[];
  loading?: boolean;
}

// MITRE ATT&CK Tactics with colors
const TACTIC_COLORS: Record<string, string> = {
  'Reconnaissance': '#00E5CC',
  'Resource Development': '#7B68EE',
  'Initial Access': '#FFB627',
  'Execution': '#DC143C',
  'Persistence': '#FF3B30',
  'Privilege Escalation': '#9B9B9B',
  'Defense Evasion': '#00E5CC',
  'Credential Access': '#7B68EE',
  'Discovery': '#FFB627',
  'Lateral Movement': '#DC143C',
  'Collection': '#FF3B30',
  'Command and Control': '#9B9B9B',
  'Exfiltration': '#00E5CC',
  'Impact': '#FFB627',
};

export function AttackHistogramChart({ histogramData, loading = false }: AttackHistogramChartProps) {
  // Transform histogram data for recharts (pivot by tactic)
  const getChartData = (): TacticChartData[] => {
    if (histogramData.length === 0) return [];

    // Calculate time span to determine if we need to show dates
    const timestamps = histogramData.map(item => new Date(item.time_bucket).getTime());
    const minTime = Math.min(...timestamps);
    const maxTime = Math.max(...timestamps);
    const timeSpanHours = (maxTime - minTime) / (1000 * 60 * 60);
    const showDate = timeSpanHours > 24;

    // Group by time bucket
    const buckets = new Map<string, TacticChartData>();

    histogramData.forEach(item => {
      const date = new Date(item.time_bucket);
      const timeKey = showDate
        ? date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
          })
        : date.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit'
          });

      if (!buckets.has(timeKey)) {
        buckets.set(timeKey, { time: timeKey });
      }

      const bucket = buckets.get(timeKey)!;
      bucket[item.tactic_name] = (bucket[item.tactic_name] as number || 0) + item.attack_count;
    });

    return Array.from(buckets.values()).reverse();
  };

  const chartData = getChartData();
  const uniqueTactics = [...new Set(histogramData.map(d => d.tactic_name))].filter(Boolean);

  return (
    <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
      <div className="mb-4">
        <h2 className="text-xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
          ATTACK_DISTRIBUTION
        </h2>
        <div className="text-xs text-ghost">Stacked histogram showing attack distribution</div>
      </div>

      {loading ? (
        <div className="h-64 flex items-center justify-center text-ghost">
          [LOADING_DATA...]
        </div>
      ) : chartData.length > 0 ? (
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={chartData} barCategoryGap={0}>
            <XAxis
              dataKey="time"
              stroke="#9B9B9B"
              style={{ fontSize: '10px', fontFamily: 'monospace' }}
            />
            <YAxis
              stroke="#9B9B9B"
              style={{ fontSize: '10px', fontFamily: 'monospace' }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#FFFFFF',
                border: '1px solid #1A1A1D',
                fontFamily: 'monospace',
                fontSize: '12px'
              }}
            />
            {uniqueTactics.map(tactic => (
              <Bar
                key={tactic}
                dataKey={tactic}
                stackId="a"
                fill={TACTIC_COLORS[tactic] || '#9B9B9B'}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <div className="h-64 flex items-center justify-center text-ghost">
          [NO_DATA_AVAILABLE]
        </div>
      )}
    </div>
  );
}
