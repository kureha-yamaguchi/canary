import { useState, useEffect } from 'react'
import { Attack } from '../types'

interface AttackFiltersProps {
  attacks: Attack[]
  stats: {
    websites: string[]
    vulnerabilities: string[]
    techniques: string[]
    ips: string[]
  }
  onFilterChange: (filtered: Attack[]) => void
}

export function AttackFilters({ attacks, stats, onFilterChange }: AttackFiltersProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedWebsite, setSelectedWebsite] = useState<string>('')
  const [selectedVulnerability, setSelectedVulnerability] = useState<string>('')
  const [selectedTechnique, setSelectedTechnique] = useState<string>('')
  const [selectedIp, setSelectedIp] = useState<string>('')
  const [successFilter, setSuccessFilter] = useState<'all' | 'success' | 'failed'>('all')
  const [dateRange, setDateRange] = useState<'all' | '24h' | '7d' | '30d'>('all')

  const applyFilters = () => {
    let filtered = [...attacks]

    // Search term (matches any field)
    if (searchTerm) {
      const term = searchTerm.toLowerCase()
      filtered = filtered.filter(attack =>
        attack.website_url.toLowerCase().includes(term) ||
        attack.vulnerability_type.toLowerCase().includes(term) ||
        attack.source_ip.toLowerCase().includes(term) ||
        attack.technique_id.toLowerCase().includes(term) ||
        attack.session_id.toLowerCase().includes(term) ||
        attack.id.toLowerCase().includes(term)
      )
    }

    // Website filter
    if (selectedWebsite) {
      filtered = filtered.filter(attack => attack.website_url === selectedWebsite)
    }

    // Vulnerability filter
    if (selectedVulnerability) {
      filtered = filtered.filter(attack => attack.vulnerability_type === selectedVulnerability)
    }

    // Technique filter
    if (selectedTechnique) {
      filtered = filtered.filter(attack => attack.technique_id === selectedTechnique)
    }

    // IP filter
    if (selectedIp) {
      filtered = filtered.filter(attack => attack.source_ip === selectedIp)
    }

    // Success filter
    if (successFilter !== 'all') {
      filtered = filtered.filter(attack =>
        successFilter === 'success' ? attack.success : !attack.success
      )
    }

    // Date range filter
    if (dateRange !== 'all') {
      const now = new Date()
      const cutoff = new Date()
      switch (dateRange) {
        case '24h':
          cutoff.setHours(now.getHours() - 24)
          break
        case '7d':
          cutoff.setDate(now.getDate() - 7)
          break
        case '30d':
          cutoff.setDate(now.getDate() - 30)
          break
      }
      filtered = filtered.filter(attack => new Date(attack.timestamp) >= cutoff)
    }

    onFilterChange(filtered)
  }

  // Apply filters when any filter changes
  useEffect(() => {
    applyFilters()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchTerm, selectedWebsite, selectedVulnerability, selectedTechnique, selectedIp, successFilter, dateRange, attacks])

  const clearFilters = () => {
    setSearchTerm('')
    setSelectedWebsite('')
    setSelectedVulnerability('')
    setSelectedTechnique('')
    setSelectedIp('')
    setSuccessFilter('all')
    setDateRange('all')
    onFilterChange(attacks)
  }

  return (
    <div className="bg-slate-800 rounded-lg shadow-lg p-6 mb-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xl font-bold text-white">Filter & Search Attacks</h3>
        <button
          onClick={clearFilters}
          className="text-sm text-slate-400 hover:text-white transition-colors"
        >
          Clear All
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Search */}
        <div className="lg:col-span-3">
          <label className="block text-sm text-slate-400 mb-2">Search</label>
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value)
              applyFilters()
            }}
            placeholder="Search by URL, IP, vulnerability, technique, session ID..."
            className="w-full px-4 py-2 bg-slate-700 text-white rounded-lg border border-slate-600 focus:border-blue-500 focus:outline-none"
          />
        </div>

        {/* Success Filter */}
        <div>
          <label className="block text-sm text-slate-400 mb-2">Status</label>
          <select
            value={successFilter}
            onChange={(e) => {
              setSuccessFilter(e.target.value as 'all' | 'success' | 'failed')
              applyFilters()
            }}
            className="w-full px-4 py-2 bg-slate-700 text-white rounded-lg border border-slate-600 focus:border-blue-500 focus:outline-none"
          >
            <option value="all">All Attacks</option>
            <option value="success">Successful Only</option>
            <option value="failed">Failed Only</option>
          </select>
        </div>

        {/* Date Range */}
        <div>
          <label className="block text-sm text-slate-400 mb-2">Time Range</label>
          <select
            value={dateRange}
            onChange={(e) => {
              setDateRange(e.target.value as 'all' | '24h' | '7d' | '30d')
              applyFilters()
            }}
            className="w-full px-4 py-2 bg-slate-700 text-white rounded-lg border border-slate-600 focus:border-blue-500 focus:outline-none"
          >
            <option value="all">All Time</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
        </div>

        {/* Website Filter */}
        <div>
          <label className="block text-sm text-slate-400 mb-2">Website</label>
          <select
            value={selectedWebsite}
            onChange={(e) => {
              setSelectedWebsite(e.target.value)
              applyFilters()
            }}
            className="w-full px-4 py-2 bg-slate-700 text-white rounded-lg border border-slate-600 focus:border-blue-500 focus:outline-none"
          >
            <option value="">All Websites</option>
            {stats.websites.map(url => (
              <option key={url} value={url}>{url}</option>
            ))}
          </select>
        </div>

        {/* Vulnerability Filter */}
        <div>
          <label className="block text-sm text-slate-400 mb-2">Vulnerability Type</label>
          <select
            value={selectedVulnerability}
            onChange={(e) => {
              setSelectedVulnerability(e.target.value)
              applyFilters()
            }}
            className="w-full px-4 py-2 bg-slate-700 text-white rounded-lg border border-slate-600 focus:border-blue-500 focus:outline-none"
          >
            <option value="">All Vulnerabilities</option>
            {stats.vulnerabilities.map(vuln => (
              <option key={vuln} value={vuln}>{vuln}</option>
            ))}
          </select>
        </div>

        {/* Technique Filter */}
        <div>
          <label className="block text-sm text-slate-400 mb-2">MITRE Technique</label>
          <select
            value={selectedTechnique}
            onChange={(e) => {
              setSelectedTechnique(e.target.value)
              applyFilters()
            }}
            className="w-full px-4 py-2 bg-slate-700 text-white rounded-lg border border-slate-600 focus:border-blue-500 focus:outline-none"
          >
            <option value="">All Techniques</option>
            {stats.techniques.map(tech => (
              <option key={tech} value={tech}>{tech}</option>
            ))}
          </select>
        </div>

        {/* IP Filter */}
        <div>
          <label className="block text-sm text-slate-400 mb-2">Source IP</label>
          <select
            value={selectedIp}
            onChange={(e) => {
              setSelectedIp(e.target.value)
              applyFilters()
            }}
            className="w-full px-4 py-2 bg-slate-700 text-white rounded-lg border border-slate-600 focus:border-blue-500 focus:outline-none"
          >
            <option value="">All IPs</option>
            {stats.ips.map(ip => (
              <option key={ip} value={ip}>{ip}</option>
            ))}
          </select>
        </div>
      </div>
    </div>
  )
}

