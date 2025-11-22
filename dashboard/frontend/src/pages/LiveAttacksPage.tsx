import { useState, useEffect } from 'react'
import { RealTimeFeed } from '../components/RealTimeFeed'
import { StatsOverview } from '../components/StatsOverview'
import { KeyMetrics } from '../components/KeyMetrics'
import { AttackFilters } from '../components/AttackFilters'
import { SyntheticDataToggle } from '../components/SyntheticDataToggle'
import { useWebSocket } from '../hooks/useWebSocket'
import { Attack, Stats } from '../types'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export function LiveAttacksPage() {
  const [attacks, setAttacks] = useState<Attack[]>([])
  const [filteredAttacks, setFilteredAttacks] = useState<Attack[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [includeSynthetic, setIncludeSynthetic] = useState(false)
  const wsUrl = API_BASE.replace(/^http/, 'ws')
  const { lastMessage, readyState } = useWebSocket(`${wsUrl}/ws`)

  // Handle new attack from WebSocket
  useEffect(() => {
    if (lastMessage?.type === 'new_attack') {
      setAttacks(prev => {
        const updated = [lastMessage.data, ...prev].slice(0, 100) // Keep last 100
        setFilteredAttacks(updated) // Initially show all attacks
        return updated
      })
      // Refresh stats when new attack comes in
      fetchStats()
    }
  }, [lastMessage])

  // Initialize filtered attacks when attacks load
  useEffect(() => {
    if (attacks.length > 0 && filteredAttacks.length === 0) {
      setFilteredAttacks(attacks)
    }
  }, [attacks, filteredAttacks.length])

  const fetchStats = async () => {
    try {
      const url = `${API_BASE}/api/stats?include_synthetic=${includeSynthetic}`
      const response = await fetch(url)
      const data = await response.json()
      setStats(data)
    } catch (error) {
      console.error('Error fetching stats:', error)
    }
  }

  const fetchAttacks = async () => {
    try {
      const url = `${API_BASE}/api/attacks?limit=1000&include_synthetic=${includeSynthetic}`
      const response = await fetch(url)
      const attacksData = await response.json()
      setAttacks(attacksData)
      setFilteredAttacks(attacksData)
    } catch (error) {
      console.error('Error fetching attacks:', error)
    }
  }

  // Fetch initial data
  useEffect(() => {
    fetchStats()
    fetchAttacks()
    
    const interval = setInterval(() => {
      fetchStats()
    }, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [])

  // Refetch when synthetic toggle changes
  useEffect(() => {
    fetchStats()
    fetchAttacks()
  }, [includeSynthetic])

  // Extract unique values for filter dropdowns
  const filterStats = stats ? {
    websites: Array.from(new Set(attacks.map(a => a.website_url))).sort(),
    vulnerabilities: Array.from(new Set(attacks.map(a => a.vulnerability_type))).sort(),
    techniques: Array.from(new Set(attacks.map(a => a.technique_id))).sort(),
    ips: Array.from(new Set(attacks.map(a => a.source_ip))).sort()
  } : {
    websites: [],
    vulnerabilities: [],
    techniques: [],
    ips: []
  }

  return (
    <div className="space-y-8">
      {/* Synthetic Data Toggle */}
      <div className="flex justify-end">
        <SyntheticDataToggle 
          includeSynthetic={includeSynthetic}
          onToggle={setIncludeSynthetic}
        />
      </div>

      {/* Key Metrics at Top */}
      {stats && <KeyMetrics stats={stats} />}

      {/* Filters */}
      {stats && attacks.length > 0 && (
        <AttackFilters
          attacks={attacks}
          stats={filterStats}
          onFilterChange={setFilteredAttacks}
        />
      )}

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div className="lg:col-span-2">
          <RealTimeFeed attacks={filteredAttacks} connectionStatus={readyState} />
        </div>
        
        {/* Quick Stats Sidebar */}
        <div className="space-y-4">
          <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
            <h3 className="text-lg font-bold text-gray-900 mb-4">Quick Stats</h3>
            {stats && (
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600">30d Attacks:</span>
                  <span className="text-gray-900 font-semibold">{stats.attacks_30d.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Success Rate:</span>
                  <span className="text-red-600 font-semibold">
                    {stats.total_attacks > 0 
                      ? ((stats.successful_attacks / stats.total_attacks) * 100).toFixed(1)
                      : 0}%
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Top Technique:</span>
                  <span className="text-gray-900 font-semibold">
                    {stats.technique_stats.length > 0 
                      ? stats.technique_stats[0].technique_id 
                      : 'N/A'}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Detailed Stats and Charts */}
      {stats && <StatsOverview stats={stats} />}
    </div>
  )
}

