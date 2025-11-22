import React, { useState, useEffect, useMemo } from 'react';
import './App.css';

const MITREAttackVisualization = () => {
  const [techniques, setTechniques] = useState({});
  const [attacks, setAttacks] = useState({}); // Map of attack_id -> array of aml_ids (preserving sequence)
  const [selectedAttackId, setSelectedAttackId] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fallback map for tactic shortnames to full names (used if JSON doesn't have tactic info)
  const tacticNameMap = {
    'reconnaissance': 'Reconnaissance',
    'resource-development': 'Resource Development',
    'initial-access': 'Initial Access',
    'execution': 'Execution',
    'persistence': 'Persistence',
    'privilege-escalation': 'Privilege Escalation',
    'defense-evasion': 'Defense Evasion',
    'credential-access': 'Credential Access',
    'discovery': 'Discovery',
    'lateral-movement': 'Lateral Movement',
    'collection': 'Collection',
    'command-and-control': 'Command and Control',
    'exfiltration': 'Exfiltration',
    'impact': 'Impact'
  };

  // Tactic order matching MITRE ATT&CK Enterprise matrix
  const tacticOrder = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
  ];

  // Map tactic names to their MITRE ATT&CK tactic IDs for URLs
  const tacticUrlMap = {
    "Reconnaissance": "TA0043",
    "Resource Development": "TA0042",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040"
  };

  // Parse CSV data and group by attack_id, preserving sequence
  const parseCSV = (csvText) => {
    const lines = csvText.trim().split('\n');
    if (lines.length < 2) {
      throw new Error('CSV file is empty or has no data rows');
    }
    
    // Parse header row
    const headers = lines[0].split(',').map(h => h.trim());
    const attackIdIndex = headers.indexOf('attack_id');
    const amlIdIndex = headers.indexOf('aml_id');
    
    if (attackIdIndex === -1) {
      throw new Error('attack_id column not found in CSV');
    }
    if (amlIdIndex === -1) {
      throw new Error('aml_id column not found in CSV');
    }
    
    // Group by attack_id, preserving sequence
    const attacksMap = {};
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line && !line.startsWith('created_at')) { // Skip header rows that might appear in middle
        const values = line.split(',').map(v => v.trim());
        const attackId = values[attackIdIndex];
        const amlId = values[amlIdIndex];
        
        if (attackId && amlId && amlId.startsWith('T')) {
          if (!attacksMap[attackId]) {
            attacksMap[attackId] = [];
          }
          attacksMap[attackId].push(amlId);
        }
      }
    }
    
    return attacksMap;
  };

  // Fetch attack mapping CSV
  const fetchAttackMapping = async () => {
    try {
      const response = await fetch('/mitre_campaigns_full.csv');
      if (!response.ok) {
        throw new Error(`Failed to fetch attack mapping: ${response.statusText}`);
      }
      const csvText = await response.text();
      const attacksMap = parseCSV(csvText);
      console.log('Loaded attacks:', Object.keys(attacksMap).length, 'campaigns');
      setAttacks(attacksMap);
      
      // Set first attack as default if no attack is selected
      const attackIds = Object.keys(attacksMap);
      if (attackIds.length > 0) {
        setSelectedAttackId(prev => prev || attackIds[0]);
        console.log('Default attack selected:', attackIds[0]);
      }
    } catch (err) {
      console.error('Error loading attack mapping CSV:', err);
      // Continue without attack mapping if CSV fails to load
      setAttacks({});
    }
  };

  useEffect(() => {
    const fetchMitreData = async () => {
      try {
        // Fetch attack mapping CSV first
        await fetchAttackMapping();
        
        // Fetch MITRE ATT&CK data
        const mitreResponse = await fetch(
          'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
        );
        const json = await mitreResponse.json();
        
        // First, build a map of tactic shortnames to full names from the JSON
        const tacticShortnameToName = {};
        json.objects.forEach(obj => {
          if (obj.type === 'x-mitre-tactic') {
            const shortname = obj.x_mitre_shortname;
            tacticShortnameToName[shortname] = obj.name;
          }
        });
        
        // Parse the data
        const techniquesByTactic = {};
        
        json.objects.forEach(obj => {
          // Get techniques (excluding sub-techniques)
          if (obj.type === 'attack-pattern' && !obj.revoked && !obj.x_mitre_deprecated) {
            const externalRefs = obj.external_references || [];
            const mitreRef = externalRefs.find(ref => ref.source_name === 'mitre-attack');
            
            if (mitreRef && mitreRef.external_id) {
              // Skip sub-techniques (they have a dot in the ID)
              if (mitreRef.external_id.includes('.')) {
                return;
              }
              
              const killChainPhases = obj.kill_chain_phases || [];
              const mitreTactics = killChainPhases
                .filter(phase => phase.kill_chain_name === 'mitre-attack')
                .map(phase => {
                  // Use the shortname to full name map we built
                  const shortname = phase.phase_name;
                  return tacticShortnameToName[shortname] || tacticNameMap[shortname] || shortname;
                })
                .filter(Boolean); // Remove any undefined/null values
              
              mitreTactics.forEach(tactic => {
                if (!techniquesByTactic[tactic]) {
                  techniquesByTactic[tactic] = [];
                }
                
                techniquesByTactic[tactic].push({
                  aml_id: mitreRef.external_id,
                  name: obj.name,
                  url: mitreRef.url
                });
              });
            }
          }
        });
        
        // Sort techniques by ID within each tactic
        Object.keys(techniquesByTactic).forEach(tactic => {
          techniquesByTactic[tactic].sort((a, b) => {
            const numA = parseInt(a.aml_id.substring(1));
            const numB = parseInt(b.aml_id.substring(1));
            return numA - numB;
          });
        });
        
        setTechniques(techniquesByTactic);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching MITRE data:', err);
        setError(err.message);
        setLoading(false);
      }
    };

    fetchMitreData();
  }, []);

  const tacticGroups = useMemo(() => {
    return techniques;
  }, [techniques]);

  // Calculate technique frequencies across all attacks
  const techniqueFrequencies = useMemo(() => {
    const frequencies = {};
    const totalAttacks = Object.keys(attacks).length;
    
    if (totalAttacks === 0) {
      return frequencies;
    }
    
    // Count how many attacks use each technique
    Object.values(attacks).forEach(attackTechniques => {
      const uniqueTechniques = new Set(attackTechniques);
      uniqueTechniques.forEach(techniqueId => {
        frequencies[techniqueId] = (frequencies[techniqueId] || 0) + 1;
      });
    });
    
    return frequencies;
  }, [attacks]);

  // Get max frequency for normalization
  const maxFrequency = useMemo(() => {
    const frequencies = Object.values(techniqueFrequencies);
    return frequencies.length > 0 ? Math.max(...frequencies) : 1;
  }, [techniqueFrequencies]);

  // Get the selected attack's techniques as a Set for fast lookup
  const selectedAttackTechniques = useMemo(() => {
    if (!selectedAttackId || !attacks[selectedAttackId]) {
      return new Set();
    }
    return new Set(attacks[selectedAttackId]);
  }, [selectedAttackId, attacks]);

  // Generate heatmap color based on frequency - three categories: low, medium, high
  const getHeatmapColor = (techniqueId) => {
    const frequency = techniqueFrequencies[techniqueId] || 0;
    
    // Normalize frequency to 0-1 range
    const normalized = maxFrequency > 0 ? frequency / maxFrequency : 0;
    
    // Three categories: low, medium, high
    if (normalized < 0.33) {
      // Low frequency - light blue
      return '#87CEEB'; // Sky blue
    } else if (normalized < 0.67) {
      // Medium frequency - orange
      return '#FFA500'; // Orange
    } else {
      // High frequency - red
      return '#FF4500'; // Red-orange
    }
  };

  if (loading) {
    return (
      <div className="matrix-container">
        <div className="loading-message">Loading MITRE ATT&CK data...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="matrix-container">
        <div className="error-message">Error loading data: {error}</div>
      </div>
    );
  }

  const attackIds = Object.keys(attacks).sort();

  return (
    <div className="matrix-container">
      <div className="matrix-header">
        <h1 className="matrix-title">Project Canary</h1>
        <p className="matrix-subtitle">Intelligence gathering on agentic adversary attack vectors. Open source knowledge base of adversary TTPs based on real-world observations on our fleet of honeypot websites</p>
      </div>
      
      {attackIds.length > 0 && (
        <div className="attack-selector">
          <label htmlFor="attack-select" className="attack-select-label">
            Select Attack Campaign:
          </label>
          <select
            id="attack-select"
            value={selectedAttackId}
            onChange={(e) => setSelectedAttackId(e.target.value)}
            className="attack-select"
          >
            {attackIds.map(attackId => (
              <option key={attackId} value={attackId}>
                {attackId} ({attacks[attackId].length} techniques)
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Heatmap Legend */}
      {maxFrequency > 0 && (
        <div className="heatmap-legend">
          <div className="heatmap-legend-title">Technique Usage Frequency</div>
          <div className="heatmap-legend-content">
            <div className="heatmap-legend-scale">
              <div className="heatmap-legend-item">
                <div className="heatmap-legend-color" style={{ backgroundColor: '#87CEEB' }}></div>
                <span>Low (0-{Math.max(0, Math.floor(maxFrequency * 0.33))} campaigns)</span>
              </div>
              <div className="heatmap-legend-item">
                <div className="heatmap-legend-color" style={{ backgroundColor: '#FFA500' }}></div>
                <span>Medium ({Math.max(1, Math.floor(maxFrequency * 0.33) + 1)}-{Math.floor(maxFrequency * 0.67)} campaigns)</span>
              </div>
              <div className="heatmap-legend-item">
                <div className="heatmap-legend-color" style={{ backgroundColor: '#FF4500' }}></div>
                <span>High ({Math.max(1, Math.floor(maxFrequency * 0.67) + 1)}-{maxFrequency} campaigns)</span>
              </div>
            </div>
            <div className="heatmap-legend-note">
              Color indicates how many attack campaigns use each technique (out of {Object.keys(attacks).length} total campaigns)
            </div>
          </div>
        </div>
      )}
      
      <div className="matrix-table">
        <table>
          <thead>
            <tr>
              {tacticOrder.map(tactic => (
                <th key={tactic} className="tactic-header">
                  <a href={`https://attack.mitre.org/tactics/${tacticUrlMap[tactic]}/`} target="_blank" rel="noopener noreferrer">
                    {tactic}
                  </a>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr>
              {tacticOrder.map(tactic => {
                const tacticTechniques = tacticGroups[tactic] || [];
                return (
                  <td key={tactic} className="tactic-column">
                    {tacticTechniques.map(technique => {
                      const isInAttack = selectedAttackTechniques.has(technique.aml_id);
                      const heatmapColor = getHeatmapColor(technique.aml_id);
                      const frequency = techniqueFrequencies[technique.aml_id] || 0;
                      return (
                        <div 
                          key={technique.aml_id} 
                          className={`technique-cell ${isInAttack ? 'attack-technique' : ''}`}
                          title={frequency > 0 ? `Used in ${frequency} out of ${Object.keys(attacks).length} attack campaigns` : 'Not used in any campaigns'}
                        >
                          <div 
                            className="technique-heatmap-bar"
                            style={{ backgroundColor: heatmapColor }}
                          ></div>
                          <a 
                            href={`https://attack.mitre.org/techniques/${technique.aml_id}/`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="technique-link"
                          >
                            <span className={`technique-name ${isInAttack ? 'attack-name' : ''}`}>
                              {technique.name}
                            </span>
                            <span className="technique-id">
                              {technique.aml_id}
                              {frequency > 0 && (
                                <span className="technique-frequency"> ({frequency})</span>
                              )}
                            </span>
                          </a>
                        </div>
                      );
                    })}
                  </td>
                );
              })}
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default MITREAttackVisualization;