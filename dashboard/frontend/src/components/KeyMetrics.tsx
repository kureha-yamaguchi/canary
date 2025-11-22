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
        color="text-blue-600"
        bgColor="bg-blue-50 border-blue-200"
      />
      <MetricCard
        title="24h Attacks"
        value={stats.attacks_24h.toLocaleString()}
        subtitle="Last 24 hours"
        color="text-amber-600"
        bgColor="bg-amber-50 border-amber-200"
      />
      <MetricCard
        title="7d Attacks"
        value={stats.attacks_7d.toLocaleString()}
        subtitle="Last 7 days"
        color="text-orange-600"
        bgColor="bg-orange-50 border-orange-200"
      />
      <MetricCard
        title="Successful"
        value={stats.successful_attacks.toLocaleString()}
        subtitle={`${successRate}% success rate`}
        color="text-red-600"
        bgColor="bg-red-50 border-red-200"
      />
      <MetricCard
        title="Failed"
        value={stats.failed_attacks.toLocaleString()}
        subtitle={`${(100 - parseFloat(successRate)).toFixed(1)}% failure rate`}
        color="text-yellow-600"
        bgColor="bg-yellow-50 border-yellow-200"
      />
      <MetricCard
        title="Websites"
        value={stats.websites_attacked.toLocaleString()}
        subtitle="Unique targets"
        color="text-green-600"
        bgColor="bg-green-50 border-green-200"
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
    <div className={`bg-white rounded-lg shadow-sm p-6 border ${bgColor}`}>
      <div className="text-sm text-gray-600 mb-1">{title}</div>
      <div className={`text-3xl font-bold ${color} mb-1`}>{value}</div>
      <div className="text-xs text-gray-500">{subtitle}</div>
    </div>
  )
}

