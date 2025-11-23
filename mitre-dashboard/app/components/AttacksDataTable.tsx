'use client';

import { useEffect, useState } from 'react';

interface Attack {
  id: string;
  timestamp: string;
  base_url: string;
  vulnerability_type: string;
  technique_id: string;
  attacker_id: string;
  session_id: string;
  success: boolean;
  is_synthetic?: boolean;
  url_path?: string;
}

interface AttacksDataTableProps {
  timeRange: number;
  includeSynthetic: boolean;
  selectedWebsites: string[];
  selectedVulnTypes: string[];
  selectedTechniques: string[];
  selectedIPs: string[];
}

export function AttacksDataTable({
  timeRange,
  includeSynthetic,
  selectedWebsites,
  selectedVulnTypes,
  selectedTechniques,
  selectedIPs,
}: AttacksDataTableProps) {
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAttacks();
  }, [timeRange, includeSynthetic, selectedWebsites, selectedVulnTypes, selectedTechniques, selectedIPs]);

  const fetchAttacks = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        timeRange: timeRange.toString(),
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

      const response = await fetch(`/api/attacks-data?${params.toString()}`);
      if (response.ok) {
        const data = await response.json();
        setAttacks(data);
      }
    } catch (error) {
      console.error('Error fetching attack data:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  };

  const downloadCSV = () => {
    // Create CSV header
    const headers = [
      'Timestamp',
      'Target URL',
      'Vulnerability Type',
      'Technique ID',
      'Source IP',
      'Session ID',
      'Success',
      'Synthetic',
      'Attack ID'
    ];

    // Create CSV rows
    const rows = attacks.map(attack => {
      const fullUrl = attack.url_path ? `${attack.base_url}${attack.url_path}` : attack.base_url;
      return [
        attack.timestamp,
        `"${fullUrl}"`, // Quote URLs to handle commas
        attack.vulnerability_type,
        attack.technique_id,
        attack.attacker_id,
        attack.session_id,
        attack.success ? 'true' : 'false',
        attack.is_synthetic ? 'true' : 'false',
        attack.id
      ];
    });

    // Combine headers and rows
    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.join(','))
    ].join('\n');

    // Create download link
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);

    link.setAttribute('href', url);
    link.setAttribute('download', `attack_data_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-6">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
            DATASET_EXPORT
          </h2>
          <div className="text-xs text-ghost">
            {attacks.length} total records
          </div>
        </div>
        <button
          onClick={downloadCSV}
          disabled={attacks.length === 0}
          className="border border-charcoal dark:border-cream bg-cyan text-charcoal px-4 py-2 text-sm font-mono hover:bg-amber transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
        >
          [DOWNLOAD_CSV]
        </button>
      </div>

      {loading ? (
        <div className="text-center py-8 text-ghost text-xs">[LOADING_DATA...]</div>
      ) : attacks.length === 0 ? (
        <div className="text-center py-8 text-ghost text-xs">[NO_DATA_AVAILABLE]</div>
      ) : (
        <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
          <table className="w-full text-xs font-mono border-collapse">
            <thead className="sticky top-0 bg-white dark:bg-charcoal">
              <tr className="border-b border-charcoal dark:border-cream">
                <th className="text-left py-2 px-2 text-ghost bg-white dark:bg-charcoal">TIMESTAMP</th>
                <th className="text-left py-2 px-2 text-ghost bg-white dark:bg-charcoal">TARGET</th>
                <th className="text-left py-2 px-2 text-ghost bg-white dark:bg-charcoal">VULN_TYPE</th>
                <th className="text-left py-2 px-2 text-ghost bg-white dark:bg-charcoal">TECHNIQUE</th>
                <th className="text-left py-2 px-2 text-ghost bg-white dark:bg-charcoal">SOURCE_IP</th>
                <th className="text-left py-2 px-2 text-ghost bg-white dark:bg-charcoal">STATUS</th>
              </tr>
            </thead>
            <tbody>
              {attacks.map((attack) => {
                const fullUrl = attack.url_path ? `${attack.base_url}${attack.url_path}` : attack.base_url;
                return (
                  <tr
                    key={attack.id}
                    className="border-b border-charcoal/20 dark:border-cream/20 hover:bg-cyan/5 transition-colors"
                  >
                    <td className="py-2 px-2 whitespace-nowrap">{formatTimestamp(attack.timestamp)}</td>
                    <td className="py-2 px-2 max-w-xs truncate" title={fullUrl}>
                      {fullUrl}
                    </td>
                    <td className="py-2 px-2">{attack.vulnerability_type}</td>
                    <td className="py-2 px-2">
                      <span className="px-2 py-0.5 bg-charcoal dark:bg-cream text-cream dark:text-charcoal">
                        {attack.technique_id}
                      </span>
                    </td>
                    <td className="py-2 px-2">{attack.attacker_id}</td>
                    <td className="py-2 px-2">
                      <span
                        className={`px-2 py-0.5 font-bold ${
                          attack.success
                            ? 'bg-crimson text-cream'
                            : 'bg-amber text-charcoal'
                        }`}
                      >
                        {attack.success ? '[SUCCESS]' : '[FAILED]'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
