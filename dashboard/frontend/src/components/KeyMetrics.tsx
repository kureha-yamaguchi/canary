import { Stats } from '../types'

interface KeyMetricsProps {
  stats: Stats
}

export function KeyMetrics({ stats }: KeyMetricsProps) {
  const successRate = stats.total_attacks > 0 
    ? ((stats.successful_attacks / stats.total_attacks) * 100).toFixed(1)
    : '0'

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
      <MetricCard
        title="Total Attacks"
        value={stats.total_attacks.toLocaleString()}
        subtitle="All time"
        color="text-blue-400"
        bgColor="bg-blue-500/10 border-blue-500/20"
      />
      <MetricCard
        title="24h Attacks"
        value={stats.attacks_24h.toLocaleString()}
        subtitle="Last 24 hours"
        color="text-yellow-400"
        bgColor="bg-yellow-500/10 border-yellow-500/20"
      />
      <MetricCard
        title="7d Attacks"
        value={stats.attacks_7d.toLocaleString()}
        subtitle="Last 7 days"
        color="text-orange-400"
        bgColor="bg-orange-500/10 border-orange-500/20"
      />
      <MetricCard
        title="Successful"
        value={stats.successful_attacks.toLocaleString()}
        subtitle={`${successRate}% success rate`}
        color="text-red-400"
        bgColor="bg-red-500/10 border-red-500/20"
      />
      <MetricCard
        title="Failed"
        value={stats.failed_attacks.toLocaleString()}
        subtitle={`${(100 - parseFloat(successRate)).toFixed(1)}% failure rate`}
        color="text-yellow-400"
        bgColor="bg-yellow-500/10 border-yellow-500/20"
      />
      <MetricCard
        title="Websites"
        value={stats.websites_attacked.toLocaleString()}
        subtitle="Unique targets"
        color="text-green-400"
        bgColor="bg-green-500/10 border-green-500/20"
      />
    </div>
  )
}

function MetricCard({ 
  title, 
  value, 
  subtitle, 
  color, 
  bgColor 
}: {
  title: string
  value: string
  subtitle: string
  color: string
  bgColor: string
}) {
  return (
    <div className={`bg-slate-800 rounded-lg shadow-lg p-6 border ${bgColor}`}>
      <div className="text-sm text-slate-400 mb-1">{title}</div>
      <div className={`text-3xl font-bold ${color} mb-1`}>{value}</div>
      <div className="text-xs text-slate-500">{subtitle}</div>
    </div>
  )
}

