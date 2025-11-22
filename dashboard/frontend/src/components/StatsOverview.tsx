import { Stats } from '../types'
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { format } from 'date-fns'
import { formatUrl, formatVulnerabilityType } from '../utils/stringUtils'
import { ChartSection } from './ChartSection'
import { SmartPieChart } from './SmartPieChart'

interface StatsOverviewProps {
  stats: Stats
}

const COLORS = ['#ef4444', '#f59e0b', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899']

export function StatsOverview({ stats }: StatsOverviewProps) {
  const timeSeriesData = stats.time_series.map(item => ({
    time: format(new Date(item.timestamp), 'HH:mm'),
    attacks: item.count
  }))

  const vulnerabilityData = stats.vulnerability_stats
    .sort((a, b) => b.total - a.total)
    .slice(0, 10)
    .map(v => ({
      name: formatVulnerabilityType(v.type, 25),
      fullName: v.type,
      total: v.total,
      successful: v.successful,
      failed: v.total - v.successful
    }))

  const websiteData = stats.website_stats
    .sort((a, b) => b.total - a.total)
    .slice(0, 10)
    .map(w => ({
      name: formatUrl(w.url, 35),
      fullName: w.url,
      total: w.total,
      successful: w.successful
    }))

  const attackVectorData = stats.attack_vectors.map(v => ({
    name: v.vector.length > 25 ? v.vector.substring(0, 25) + '...' : v.vector,
    fullName: v.vector,
    value: v.count
  }))

  const techniqueData = stats.technique_stats
    .sort((a, b) => b.total - a.total)
    .slice(0, 10)
    .map(t => ({
      name: t.technique_id,
      total: t.total,
      successful: t.successful
    }))

  return (
    <div className="space-y-6">
      {/* Charts - Collapsible Sections */}
      <div className="space-y-4">
        {/* Attack Timeline */}
        <ChartSection title="Attack Timeline (24h)" defaultExpanded={true}>
          <ResponsiveContainer width="100%" height={400}>
            <LineChart data={timeSeriesData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="time" stroke="#6b7280" />
              <YAxis stroke="#6b7280" />
              <Tooltip
                contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '8px', boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)' }}
                labelStyle={{ color: '#111827' }}
              />
              <Legend />
              <Line
                type="monotone"
                dataKey="attacks"
                stroke="#ef4444"
                strokeWidth={2}
                name="Attacks"
              />
            </LineChart>
          </ResponsiveContainer>
        </ChartSection>

        {/* Attack Vectors - Smart Pie Chart */}
        {attackVectorData.length > 0 && (
          <ChartSection title="Attack Vectors" defaultExpanded={true}>
            <SmartPieChart 
              data={attackVectorData} 
              colors={COLORS}
              maxLabels={3}
              height={400}
            />
          </ChartSection>
        )}

        {/* Top Vulnerabilities */}
        {vulnerabilityData.length > 0 && (
          <ChartSection title="Top Vulnerabilities">
            <ResponsiveContainer width="100%" height={400}>
              <BarChart data={vulnerabilityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis 
                  dataKey="name" 
                  stroke="#6b7280" 
                  angle={-45} 
                  textAnchor="end" 
                  height={120}
                  tick={{ fontSize: 12 }}
                />
                <YAxis stroke="#6b7280" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '8px', boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)' }}
                  labelStyle={{ color: '#111827' }}
                  formatter={(value: any, name: string, props: any) => {
                    if (props.payload?.fullName) {
                      return [props.payload.fullName, name]
                    }
                    return [value, name]
                  }}
                />
                <Legend />
                <Bar dataKey="successful" stackId="a" fill="#ef4444" name="Successful" />
                <Bar dataKey="failed" stackId="a" fill="#f59e0b" name="Failed" />
              </BarChart>
            </ResponsiveContainer>
          </ChartSection>
        )}

        {/* Top Websites */}
        {websiteData.length > 0 && (
          <ChartSection title="Most Targeted Websites">
            <ResponsiveContainer width="100%" height={400}>
              <BarChart data={websiteData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis 
                  dataKey="name" 
                  stroke="#6b7280" 
                  angle={-45} 
                  textAnchor="end" 
                  height={120}
                  tick={{ fontSize: 12 }}
                />
                <YAxis stroke="#6b7280" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '8px', boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)' }}
                  labelStyle={{ color: '#111827' }}
                  formatter={(value: any, name: string, props: any) => {
                    if (props.payload?.fullName) {
                      return [props.payload.fullName, name]
                    }
                    return [value, name]
                  }}
                />
                <Legend />
                <Bar dataKey="total" fill="#3b82f6" name="Total Attacks" />
                <Bar dataKey="successful" fill="#ef4444" name="Successful" />
              </BarChart>
            </ResponsiveContainer>
          </ChartSection>
        )}

        {/* MITRE Techniques */}
        {techniqueData.length > 0 && (
          <ChartSection title="MITRE ATT&CK Techniques">
            <ResponsiveContainer width="100%" height={400}>
              <BarChart data={techniqueData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis dataKey="name" stroke="#6b7280" />
                <YAxis stroke="#6b7280" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '8px', boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)' }}
                  labelStyle={{ color: '#111827' }}
                />
                <Legend />
                <Bar dataKey="total" fill="#8b5cf6" name="Total" />
                <Bar dataKey="successful" fill="#ef4444" name="Successful" />
              </BarChart>
            </ResponsiveContainer>
          </ChartSection>
        )}
      </div>

      {/* Vulnerability Lists */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
          <h3 className="text-xl font-bold text-gray-900 mb-4">Successfully Exploited</h3>
          <div className="space-y-2">
            {stats.successful_vulnerabilities.length === 0 ? (
              <p className="text-gray-500">None</p>
            ) : (
              stats.successful_vulnerabilities.map((vuln, idx) => (
                <div key={idx} className="p-2 bg-red-50 border border-red-200 rounded text-sm text-red-700 break-words" title={vuln}>
                  {formatVulnerabilityType(vuln, 50)}
                </div>
              ))
            )}
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
          <h3 className="text-xl font-bold text-gray-900 mb-4">Failed Exploitation Attempts</h3>
          <div className="space-y-2">
            {stats.failed_vulnerabilities.length === 0 ? (
              <p className="text-gray-500">None</p>
            ) : (
              stats.failed_vulnerabilities.map((vuln, idx) => (
                <div key={idx} className="p-2 bg-yellow-50 border border-yellow-200 rounded text-sm text-yellow-700 break-words" title={vuln}>
                  {formatVulnerabilityType(vuln, 50)}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function MetricCard({ title, value, subtitle, color }: {
  title: string
  value: string
  subtitle: string
  color: string
}) {
  return (
    <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
      <div className="text-sm text-gray-600 mb-1">{title}</div>
      <div className={`text-3xl font-bold ${color} mb-1`}>{value}</div>
      <div className="text-xs text-gray-500">{subtitle}</div>
    </div>
  )
}

