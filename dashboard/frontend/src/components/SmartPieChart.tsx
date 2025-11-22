import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'

interface PieData {
  name: string
  fullName: string
  value: number
}

interface SmartPieChartProps {
  data: PieData[]
  colors: string[]
  maxLabels?: number
  height?: number
}

export function SmartPieChart({ data, colors, maxLabels = 3, height = 300 }: SmartPieChartProps) {
  // Sort by value and separate top N from rest
  const sorted = [...data].sort((a, b) => b.value - a.value)
  const topN = sorted.slice(0, maxLabels)
  const others = sorted.slice(maxLabels)
  
  // Sum up "others"
  const othersTotal = others.reduce((sum, item) => sum + item.value, 0)
  
  // Combine top N with "Others"
  const chartData = [
    ...topN,
    ...(othersTotal > 0 ? [{ name: 'Others', fullName: `${others.length} other types`, value: othersTotal }] : [])
  ]

  // Custom label function - only show labels for top N
  const renderLabel = ({ name, percent, payload }: any) => {
    // Only show labels for top items, not "Others"
    if (name === 'Others' || percent < 0.05) return ''
    return `${name}: ${(percent * 100).toFixed(0)}%`
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          labelLine={false}
          label={renderLabel}
          outerRadius={Math.min(height / 4, 100)}
          fill="#8884d8"
          dataKey="value"
        >
          {chartData.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
          labelStyle={{ color: '#e2e8f0' }}
          formatter={(value: any, name: string, props: any) => {
            if (props.payload?.fullName) {
              return [props.payload.fullName, value]
            }
            return [name, value]
          }}
        />
        <Legend
          wrapperStyle={{ paddingTop: '20px' }}
          formatter={(value, entry: any) => {
            const item = chartData.find(d => d.name === value)
            if (item && item.name !== 'Others') {
              const percent = ((item.value / data.reduce((sum, d) => sum + d.value, 0)) * 100).toFixed(1)
              return `${value} (${percent}%)`
            }
            return value
          }}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

