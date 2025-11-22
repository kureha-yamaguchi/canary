import React, { useState, useEffect, useMemo } from 'react';
import './App.css';

const MITREAttackVisualization = () => {
  const [techniques, setTechniques] = useState({});
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

  useEffect(() => {
    const fetchMitreData = async () => {
      try {
        const response = await fetch(
          'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
        );
        const json = await response.json();
        
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

  return (
    <div className="matrix-container">
      <div className="matrix-header">
        <h1 className="matrix-title">Project Canary</h1>
        <p className="matrix-subtitle">Intelligence gathering on agentic adversary attack vectors. Open source knowledge base of adversary TTPs based on real-world observations on our fleet of honeypot websites</p>
      </div>
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
                    {tacticTechniques.map(technique => (
                      <div key={technique.aml_id} className="technique-cell">
                        <a 
                          href={`https://attack.mitre.org/techniques/${technique.aml_id}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="technique-link"
                        >
                          <span className="technique-name">{technique.name}</span>
                          <span className="technique-id">{technique.aml_id}</span>
                        </a>
                      </div>
                    ))}
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