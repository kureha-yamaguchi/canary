'use client';

import { useState, useEffect, useRef } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { LiveAttacksFeed } from '../components/LiveAttacksFeed';

interface HistogramDataPoint {
  time_bucket: string;
  tactic: string;
  tactic_name: string;
  attack_count: number;
}

interface Stats {
  total_attacks: number;
  successful_attacks: number;
  unique_targets: number;
  unique_techniques: number;
}

interface FilterOptions {
  websites: string[];
  vuln_types: string[];
  techniques: string[];
  ips: string[];
}

interface TacticChartData {
  time: string;
  [key: string]: number | string;
}

const TIME_RANGES = [
  { label: 'Last 5 mins', minutes: 5 },
  { label: 'Last 10 mins', minutes: 10 },
  { label: 'Last 30 mins', minutes: 30 },
  { label: 'Last 1 hr', minutes: 60 },
  { label: 'Last 2 hrs', minutes: 120 },
  { label: 'Last 12 hrs', minutes: 720 },
  { label: 'Last 24 hrs', minutes: 1440 },
  { label: 'Last week', minutes: 10080 },
  { label: 'Last month', minutes: 43200 },
  { label: 'Custom', minutes: -1 },
];

const TIME_UNITS = [
  { label: 'Minutes', value: 'minutes', multiplier: 1 },
  { label: 'Hours', value: 'hours', multiplier: 60 },
  { label: 'Months', value: 'months', multiplier: 43200 },
];

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

export default function DashboardPage() {
  const [histogramData, setHistogramData] = useState<HistogramDataPoint[]>([]);
  const [stats, setStats] = useState<Stats>({
    total_attacks: 0,
    successful_attacks: 0,
    unique_targets: 0,
    unique_techniques: 0
  });
  const [filterOptions, setFilterOptions] = useState<FilterOptions>({
    websites: [],
    vuln_types: [],
    techniques: [],
    ips: []
  });
  const [loading, setLoading] = useState(true);

  // Filters
  const [timeRange, setTimeRange] = useState(1440); // 24 hours default
  const [isCustomTimeRange, setIsCustomTimeRange] = useState(false);
  const [customValue, setCustomValue] = useState(1);
  const [customUnit, setCustomUnit] = useState<'minutes' | 'hours' | 'months'>('hours');
  const [selectedWebsites, setSelectedWebsites] = useState<string[]>([]);
  const [selectedVulnTypes, setSelectedVulnTypes] = useState<string[]>([]);
  const [selectedTechniques, setSelectedTechniques] = useState<string[]>([]);
  const [selectedIPs, setSelectedIPs] = useState<string[]>([]);
  const [includeSynthetic, setIncludeSynthetic] = useState(false);

  // Dropdown states for filter sections
  const [websitesOpen, setWebsitesOpen] = useState(false);
  const [vulnTypesOpen, setVulnTypesOpen] = useState(false);
  const [techniquesOpen, setTechniquesOpen] = useState(false);
  const [ipsOpen, setIpsOpen] = useState(false);

  // Refs for dropdown containers
  const websitesRef = useRef<HTMLDivElement>(null);
  const vulnTypesRef = useRef<HTMLDivElement>(null);
  const techniquesRef = useRef<HTMLDivElement>(null);
  const ipsRef = useRef<HTMLDivElement>(null);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        websitesRef.current && !websitesRef.current.contains(event.target as Node) &&
        vulnTypesRef.current && !vulnTypesRef.current.contains(event.target as Node) &&
        techniquesRef.current && !techniquesRef.current.contains(event.target as Node) &&
        ipsRef.current && !ipsRef.current.contains(event.target as Node)
      ) {
        setWebsitesOpen(false);
        setVulnTypesOpen(false);
        setTechniquesOpen(false);
        setIpsOpen(false);
      }
    };

    if (websitesOpen || vulnTypesOpen || techniquesOpen || ipsOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [websitesOpen, vulnTypesOpen, techniquesOpen, ipsOpen]);

  // Convert minutes to custom value and unit
  const convertMinutesToCustom = (minutes: number): { value: number; unit: 'minutes' | 'hours' | 'months' } => {
    // Try months first (30 days = 43200 minutes)
    if (minutes >= 43200 && minutes % 43200 === 0) {
      return { value: minutes / 43200, unit: 'months' };
    }
    // Try hours
    if (minutes >= 60 && minutes % 60 === 0) {
      return { value: minutes / 60, unit: 'hours' };
    }
    // Default to minutes
    return { value: minutes, unit: 'minutes' };
  };

  // Calculate effective time range in minutes
  const getEffectiveTimeRange = (): number => {
    if (isCustomTimeRange) {
      const unit = TIME_UNITS.find(u => u.value === customUnit);
      return customValue * (unit?.multiplier || 1);
    }
    return timeRange;
  };

  // Clear all filters and refresh
  const clearFilters = () => {
    setSelectedWebsites([]);
    setSelectedVulnTypes([]);
    setSelectedTechniques([]);
    setSelectedIPs([]);
    // Fetch data after clearing filters
    setTimeout(() => fetchData(), 0);
  };

  // Apply filters and refresh
  const applyFilters = () => {
    fetchData();
  };

  // Toggle checkbox selection
  const toggleSelection = (value: string, selected: string[], setSelected: (values: string[]) => void) => {
    if (selected.includes(value)) {
      setSelected(selected.filter(v => v !== value));
    } else {
      setSelected([...selected, value]);
    }
  };

  // Auto-refresh only for time range and synthetic data
  useEffect(() => {
    fetchData();
  }, [timeRange, isCustomTimeRange, customValue, customUnit, includeSynthetic]);

  const fetchData = async () => {
    setLoading(true);

    try {
      // Get effective time range
      const effectiveTimeRange = getEffectiveTimeRange();

      // Determine bucket size based on time range
      const bucketMinutes = effectiveTimeRange <= 60 ? 5 : effectiveTimeRange <= 720 ? 30 : 60;

      // Build query parameters
      const params = new URLSearchParams({
        timeRange: effectiveTimeRange.toString(),
        bucketMinutes: bucketMinutes.toString(),
        includeSynthetic: includeSynthetic.toString(),
      });

      if (selectedWebsites.length > 0) {
        params.append('websites', selectedWebsites.join(','));
      }
      if (selectedVulnTypes.length > 0) {
        params.append('vulnTypes', selectedVulnTypes.join(','));
      }
      if (selectedTechniques.length > 0) {
        params.append('techniques', selectedTechniques.join(','));
      }
      if (selectedIPs.length > 0) {
        params.append('ips', selectedIPs.join(','));
      }

      // Call API route
      const response = await fetch(`/api/attacks?${params.toString()}`);

      if (!response.ok) {
        const error = await response.json();
        console.error('Error fetching data:', error);
        setLoading(false);
        return;
      }

      const data = await response.json();
      console.log('API Response:', data);

      setHistogramData(data.histogram || []);
      setStats(data.stats || {
        total_attacks: 0,
        successful_attacks: 0,
        unique_targets: 0,
        unique_techniques: 0
      });
      setFilterOptions(data.filters || {
        websites: [],
        vuln_types: [],
        techniques: [],
        ips: []
      });
    } catch (error) {
      console.error('Error fetching data:', error);
    }

    setLoading(false);
  };

  // Transform histogram data for recharts (pivot by tactic)
  const getChartData = (): TacticChartData[] => {
    if (histogramData.length === 0) return [];

    // Group by time bucket
    const buckets = new Map<string, TacticChartData>();

    histogramData.forEach(item => {
      const timeKey = new Date(item.time_bucket).toLocaleTimeString('en-US', {
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
  const successRate = stats.total_attacks > 0
    ? ((stats.successful_attacks / stats.total_attacks) * 100).toFixed(1)
    : '0.0';

  return (
    <div className="min-h-screen relative bg-[#F5F5F7] dark:bg-charcoal">
      {/* Header */}
      <div className="border-b border-charcoal dark:border-cream bg-white dark:bg-charcoal">
        <div className="px-6 py-4">
          <h1 className="text-4xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
            LIVE_DASHBOARD
          </h1>
          <div className="text-xs text-ghost">/system/monitoring/realtime</div>
        </div>
      </div>

      <div className="px-6 py-6 space-y-6">
        {/* Filters */}
        <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
          <div className="space-y-4">
            {/* Time Range Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-ghost block mb-2">TIME_RANGE</label>
                <select
                  value={timeRange}
                  onChange={(e) => {
                    const value = Number(e.target.value);
                    const previousTimeRange = timeRange === -1 ? getEffectiveTimeRange() : timeRange;

                    if (value === -1) {
                      // Switching to custom - set defaults based on previous selection
                      const converted = convertMinutesToCustom(previousTimeRange);
                      setCustomValue(converted.value);
                      setCustomUnit(converted.unit);
                      setIsCustomTimeRange(true);
                    } else {
                      setIsCustomTimeRange(false);
                    }

                    setTimeRange(value);
                  }}
                  className="w-full border border-charcoal dark:border-cream bg-white dark:bg-charcoal text-charcoal dark:text-cream px-3 py-2 text-sm font-mono"
                >
                  {TIME_RANGES.map(range => (
                    <option key={range.minutes} value={range.minutes}>
                      {range.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Synthetic Toggle */}
              <div>
                <label className="text-xs text-ghost block mb-2">SYNTHETIC_DATA</label>
                <button
                  onClick={() => setIncludeSynthetic(!includeSynthetic)}
                  className={`w-full border border-charcoal dark:border-cream px-3 py-2 text-sm font-mono transition-colors ${
                    includeSynthetic
                      ? 'bg-cyan text-charcoal'
                      : 'bg-white dark:bg-charcoal text-charcoal dark:text-cream'
                  }`}
                >
                  [{includeSynthetic ? 'INCLUDED' : 'EXCLUDED'}]
                </button>
              </div>
            </div>

            {/* Custom Time Inputs */}
            {isCustomTimeRange && (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-ghost block mb-2">CUSTOM_VALUE</label>
                  <input
                    type="number"
                    min="1"
                    value={customValue}
                    onChange={(e) => setCustomValue(Number(e.target.value))}
                    className="w-full border border-charcoal dark:border-cream bg-white dark:bg-charcoal text-charcoal dark:text-cream px-3 py-2 text-sm font-mono"
                    placeholder="Enter value"
                  />
                </div>
                <div>
                  <label className="text-xs text-ghost block mb-2">CUSTOM_UNIT</label>
                  <select
                    value={customUnit}
                    onChange={(e) => setCustomUnit(e.target.value as 'minutes' | 'hours' | 'months')}
                    className="w-full border border-charcoal dark:border-cream bg-white dark:bg-charcoal text-charcoal dark:text-cream px-3 py-2 text-sm font-mono"
                  >
                    {TIME_UNITS.map(unit => (
                      <option key={unit.value} value={unit.value}>
                        {unit.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            )}

            {/* Filters and Clear Button Row */}
            <div className="flex flex-wrap gap-4 items-start">
              {/* Websites */}
              <div ref={websitesRef} className="relative flex-1 min-w-[150px]">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setWebsitesOpen(!websitesOpen);
                    setVulnTypesOpen(false);
                    setTechniquesOpen(false);
                    setIpsOpen(false);
                  }}
                  className="w-full border border-charcoal dark:border-cream px-4 py-2 text-left text-sm font-mono bg-white dark:bg-charcoal hover:bg-cyan hover:text-charcoal dark:hover:bg-cyan transition-colors flex justify-between items-center"
                >
                  <span>WEBSITES {selectedWebsites.length > 0 && `(${selectedWebsites.length})`}</span>
                  <span>{websitesOpen ? '▼' : '▶'}</span>
                </button>
                {websitesOpen && (
                  <div
                    className="absolute z-10 w-full mt-1 border border-charcoal dark:border-cream bg-white dark:bg-charcoal max-h-60 overflow-y-auto"
                    onMouseDown={(e) => e.stopPropagation()}
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="px-4 py-3">
                      {filterOptions.websites.map(website => (
                        <div
                          key={website}
                          className="flex items-center gap-2 py-1 text-sm font-mono cursor-pointer hover:text-cyan"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleSelection(website, selectedWebsites, setSelectedWebsites);
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={selectedWebsites.includes(website)}
                            onChange={() => {}}
                            className="cursor-pointer pointer-events-none"
                          />
                          <span>{website}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Vulnerability Types */}
              <div ref={vulnTypesRef} className="relative flex-1 min-w-[150px]">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setVulnTypesOpen(!vulnTypesOpen);
                    setWebsitesOpen(false);
                    setTechniquesOpen(false);
                    setIpsOpen(false);
                  }}
                  className="w-full border border-charcoal dark:border-cream px-4 py-2 text-left text-sm font-mono bg-white dark:bg-charcoal hover:bg-cyan hover:text-charcoal dark:hover:bg-cyan transition-colors flex justify-between items-center"
                >
                  <span>VULN_TYPES {selectedVulnTypes.length > 0 && `(${selectedVulnTypes.length})`}</span>
                  <span>{vulnTypesOpen ? '▼' : '▶'}</span>
                </button>
                {vulnTypesOpen && (
                  <div
                    className="absolute z-10 w-full mt-1 border border-charcoal dark:border-cream bg-white dark:bg-charcoal max-h-60 overflow-y-auto"
                    onMouseDown={(e) => e.stopPropagation()}
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="px-4 py-3">
                      {filterOptions.vuln_types.map(type => (
                        <div
                          key={type}
                          className="flex items-center gap-2 py-1 text-sm font-mono cursor-pointer hover:text-cyan"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleSelection(type, selectedVulnTypes, setSelectedVulnTypes);
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={selectedVulnTypes.includes(type)}
                            onChange={() => {}}
                            className="cursor-pointer pointer-events-none"
                          />
                          <span>{type}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Techniques */}
              <div ref={techniquesRef} className="relative flex-1 min-w-[150px]">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setTechniquesOpen(!techniquesOpen);
                    setWebsitesOpen(false);
                    setVulnTypesOpen(false);
                    setIpsOpen(false);
                  }}
                  className="w-full border border-charcoal dark:border-cream px-4 py-2 text-left text-sm font-mono bg-white dark:bg-charcoal hover:bg-cyan hover:text-charcoal dark:hover:bg-cyan transition-colors flex justify-between items-center"
                >
                  <span>TECHNIQUES {selectedTechniques.length > 0 && `(${selectedTechniques.length})`}</span>
                  <span>{techniquesOpen ? '▼' : '▶'}</span>
                </button>
                {techniquesOpen && (
                  <div
                    className="absolute z-10 w-full mt-1 border border-charcoal dark:border-cream bg-white dark:bg-charcoal max-h-60 overflow-y-auto"
                    onMouseDown={(e) => e.stopPropagation()}
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="px-4 py-3">
                      {filterOptions.techniques.map(technique => (
                        <div
                          key={technique}
                          className="flex items-center gap-2 py-1 text-sm font-mono cursor-pointer hover:text-cyan"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleSelection(technique, selectedTechniques, setSelectedTechniques);
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={selectedTechniques.includes(technique)}
                            onChange={() => {}}
                            className="cursor-pointer pointer-events-none"
                          />
                          <span>{technique}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Source IPs */}
              <div ref={ipsRef} className="relative flex-1 min-w-[150px]">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setIpsOpen(!ipsOpen);
                    setWebsitesOpen(false);
                    setVulnTypesOpen(false);
                    setTechniquesOpen(false);
                  }}
                  className="w-full border border-charcoal dark:border-cream px-4 py-2 text-left text-sm font-mono bg-white dark:bg-charcoal hover:bg-cyan hover:text-charcoal dark:hover:bg-cyan transition-colors flex justify-between items-center"
                >
                  <span>SOURCE_IPS {selectedIPs.length > 0 && `(${selectedIPs.length})`}</span>
                  <span>{ipsOpen ? '▼' : '▶'}</span>
                </button>
                {ipsOpen && (
                  <div
                    className="absolute z-10 w-full mt-1 border border-charcoal dark:border-cream bg-white dark:bg-charcoal max-h-60 overflow-y-auto"
                    onMouseDown={(e) => e.stopPropagation()}
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="px-4 py-3">
                      {filterOptions.ips.map(ip => (
                        <div
                          key={ip}
                          className="flex items-center gap-2 py-1 text-sm font-mono cursor-pointer hover:text-cyan"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleSelection(ip, selectedIPs, setSelectedIPs);
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={selectedIPs.includes(ip)}
                            onChange={() => {}}
                            className="cursor-pointer pointer-events-none"
                          />
                          <span>{ip}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Apply Filters Button */}
              <button
                onClick={applyFilters}
                className="border border-charcoal dark:border-cream bg-cyan text-charcoal px-4 py-2 text-sm font-mono hover:bg-amber hover:text-charcoal transition-colors whitespace-nowrap"
              >
                [APPLY_FILTERS]
              </button>

              {/* Clear Filters Button */}
              <button
                onClick={clearFilters}
                className="border border-charcoal dark:border-cream bg-crimson text-cream px-4 py-2 text-sm font-mono hover:bg-cyan hover:text-charcoal transition-colors whitespace-nowrap"
              >
                [CLEAR_FILTERS]
              </button>
            </div>
          </div>
        </div>

        {/* Stats Summary */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4">
            <div className="text-xs text-ghost mb-1">TOTAL_ATTACKS</div>
            <div className="text-3xl font-bold text-cyan">{stats.total_attacks.toLocaleString()}</div>
          </div>
          <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4">
            <div className="text-xs text-ghost mb-1">SUCCESS_RATE</div>
            <div className="text-3xl font-bold text-amber">{successRate}%</div>
          </div>
          <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4">
            <div className="text-xs text-ghost mb-1">UNIQUE_TARGETS</div>
            <div className="text-3xl font-bold text-crimson">{stats.unique_targets}</div>
          </div>
          <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-4">
            <div className="text-xs text-ghost mb-1">TECHNIQUES</div>
            <div className="text-3xl font-bold text-neural-purple">{stats.unique_techniques}</div>
          </div>
        </div>

        {/* Main Content Grid - Histogram and Live Attacks */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Histogram - Takes up 2 columns */}
          <div className="lg:col-span-2 border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
            <div className="mb-4">
              <h2 className="text-xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
                ATTACK_VOLUME_BY_TACTIC
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

          {/* Live Attacks Feed - Takes up 1 column */}
          <div className="lg:col-span-1">
            <LiveAttacksFeed includeSynthetic={includeSynthetic} />
          </div>
        </div>
      </div>
    </div>
  );
}
