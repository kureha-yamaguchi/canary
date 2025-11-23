import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { RealTimeFeed } from '../components/RealTimeFeed'
import { StatsOverview } from '../components/StatsOverview'
import { KeyMetrics } from '../components/KeyMetrics'
import { AttackFilters } from '../components/AttackFilters'
import { SyntheticDataToggle } from '../components/SyntheticDataToggle'
import { useWebSocket } from '../hooks/useWebSocket'
import { Attack, Stats } from '../types'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const FEATURES = [
  {
    icon: '🔍',
    title: 'AI Agent Detection',
    description: 'Distinguish between human attackers, automated scripts, and AI agents using behavioral fingerprinting.',
    link: '/agent-trajectory',
    linkText: 'Classification →',
  },
  {
    icon: '🎯',
    title: 'TTP Prediction',
    description: 'Predict attack trajectories and recommend mitigations before attacks complete.',
    link: '/ttp-prediction',
    linkText: 'Prediction →',
  },
  {
    icon: '🗺️',
    title: 'MITRE ATT&CK Mapping',
    description: 'Map observed techniques to the MITRE ATT&CK framework for standardized threat intelligence.',
    link: '/matrix-map',
    linkText: 'View Matrix →',
  },
]

export function LiveAttacksPage() {
  const [attacks, setAttacks] = useState<Attack[]>([])
  const [filteredAttacks, setFilteredAttacks] = useState<Attack[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [includeSynthetic, setIncludeSynthetic] = useState(false)
  const [showDashboard, setShowDashboard] = useState(true)
  const wsUrl = API_BASE.replace(/^http/, 'ws')
  const { lastMessage, readyState } = useWebSocket(`${wsUrl}/ws`)

  useEffect(() => {
    if (lastMessage?.type === 'new_attack') {
      setAttacks(prev => {
        const updated = [lastMessage.data, ...prev].slice(0, 100)
        setFilteredAttacks(updated)
        return updated
      })
      fetchStats()
    }
  }, [lastMessage])

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

  useEffect(() => {
    fetchStats()
    fetchAttacks()

    const interval = setInterval(() => {
      fetchStats()
    }, 30000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    fetchStats()
    fetchAttacks()
  }, [includeSynthetic])

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
      {/* Hero Section */}
      <div className="bg-gradient-to-br from-slate-900 via-slate-800 to-indigo-900 rounded-2xl p-8 text-white">
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-white/10 rounded-full text-sm mb-4">
            <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
            Monitoring Active
          </div>
          <h1 className="text-3xl font-bold mb-3">
            AI Agent Threat Intelligence
          </h1>
          <p className="text-slate-300 text-lg mb-6">
            Deploy honeypots to measure AI agent capabilities, identify attackers through behavioral analysis,
            and predict attack trajectories before they complete.
          </p>
          <div className="flex flex-wrap gap-3">
            <Link
              to="/agent-trajectory"
              className="px-5 py-2.5 bg-white text-slate-900 rounded-lg font-medium hover:bg-slate-100 transition-colors"
            >
              Start Classification
            </Link>
            <Link
              to="/ttp-prediction"
              className="px-5 py-2.5 bg-white/10 text-white rounded-lg font-medium hover:bg-white/20 transition-colors"
            >
              View Predictions
            </Link>
          </div>
        </div>
      </div>

      {/* Feature Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {FEATURES.map((feature, i) => (
          <div key={i} className="bg-white rounded-xl border border-slate-200 p-6 hover:shadow-lg transition-shadow">
            <div className="w-12 h-12 bg-slate-100 rounded-xl flex items-center justify-center text-2xl mb-4">
              {feature.icon}
            </div>
            <h3 className="text-lg font-semibold text-slate-900 mb-2">{feature.title}</h3>
            <p className="text-slate-600 text-sm mb-4">{feature.description}</p>
            <Link to={feature.link} className="text-indigo-600 font-medium text-sm hover:text-indigo-700">
              {feature.linkText}
            </Link>
          </div>
        ))}
      </div>

      {/* Dashboard Toggle */}
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-slate-900">Live Tracking Dashboard</h2>
        <div className="flex items-center gap-4">
          <SyntheticDataToggle
            includeSynthetic={includeSynthetic}
            onToggle={setIncludeSynthetic}
          />
          <button
            onClick={() => setShowDashboard(!showDashboard)}
            className="text-sm text-slate-600 hover:text-slate-900"
          >
            {showDashboard ? 'Hide Dashboard' : 'Show Dashboard'}
          </button>
        </div>
      </div>

      {showDashboard && (
        <>
          {/* Key Metrics */}
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
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <RealTimeFeed attacks={filteredAttacks} connectionStatus={readyState} />
            </div>

            {/* Quick Stats Sidebar */}
            <div className="space-y-4">
              <div className="bg-white rounded-xl border border-slate-200 p-6">
                <h3 className="text-lg font-semibold text-slate-900 mb-4">Quick Stats</h3>
                {stats && (
                  <div className="space-y-4">
                    <div className="flex justify-between items-center py-2 border-b border-slate-100">
                      <span className="text-slate-600">30d Attacks</span>
                      <span className="text-slate-900 font-semibold">{stats.attacks_30d.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between items-center py-2 border-b border-slate-100">
                      <span className="text-slate-600">Success Rate</span>
                      <span className="text-red-600 font-semibold">
                        {stats.total_attacks > 0
                          ? ((stats.successful_attacks / stats.total_attacks) * 100).toFixed(1)
                          : 0}%
                      </span>
                    </div>
                    <div className="flex justify-between items-center py-2">
                      <span className="text-slate-600">Top Technique</span>
                      <span className="text-slate-900 font-semibold font-mono text-sm">
                        {stats.technique_stats.length > 0
                          ? stats.technique_stats[0].technique_id
                          : 'N/A'}
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {/* Quick Actions */}
              <div className="bg-white rounded-xl border border-slate-200 p-6">
                <h3 className="text-lg font-semibold text-slate-900 mb-4">Quick Actions</h3>
                <div className="space-y-2">
                  <Link
                    to="/agent-trajectory"
                    className="block w-full px-4 py-3 bg-slate-50 hover:bg-slate-100 rounded-lg text-sm font-medium text-slate-700 transition-colors"
                  >
                    <span className="mr-2">🔍</span>
                    Classify New Session
                  </Link>
                  <Link
                    to="/ttp-prediction"
                    className="block w-full px-4 py-3 bg-slate-50 hover:bg-slate-100 rounded-lg text-sm font-medium text-slate-700 transition-colors"
                  >
                    <span className="mr-2">🎯</span>
                    Run TTP Prediction
                  </Link>
                  <Link
                    to="/matrix-map"
                    className="block w-full px-4 py-3 bg-slate-50 hover:bg-slate-100 rounded-lg text-sm font-medium text-slate-700 transition-colors"
                  >
                    <span className="mr-2">🗺️</span>
                    View Attack Campaigns
                  </Link>
                </div>
              </div>
            </div>
          </div>

          {/* Detailed Stats */}
          {stats && <StatsOverview stats={stats} />}
        </>
      )}
    </div>
  )
}
