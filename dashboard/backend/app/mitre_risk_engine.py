"""MITRE ATT&CK-based risk classification and projection engine"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from collections import defaultdict
import pandas as pd
import numpy as np
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler

from app.models import Attack


@dataclass
class MitreTacticRisk:
    """Risk assessment for a MITRE tactic"""
    tactic_id: str
    tactic_name: str
    risk_score: float  # 0-100
    attack_count: int
    successful_count: int
    unique_techniques: int
    exposure_score: float
    trend: str  # 'increasing', 'stable', 'decreasing'
    trend_score: float
    techniques: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class MitreTechniqueRisk:
    """Risk assessment for a MITRE technique"""
    technique_id: str
    technique_name: str
    risk_score: float  # 0-100
    attack_count: int
    successful_count: int
    success_rate: float
    recent_activity: int  # attacks in last 24h
    trend: str
    tactics: List[str] = field(default_factory=list)
    severity_multiplier: float = 1.0  # Based on technique impact


@dataclass
class RiskProjection:
    """Risk projection for a future time period"""
    time_horizon: str  # '24h', '7d', '30d'
    predicted_attacks: int
    predicted_techniques: int
    predicted_tactics: int
    high_risk_tactics: List[str]
    high_risk_techniques: List[str]
    confidence: float
    risk_trajectory: List[Dict[str, Any]]


class MitreRiskClassificationEngine:
    """Classify and score risk based on MITRE ATT&CK framework"""
    
    # MITRE tactic severity weights (higher = more dangerous)
    TACTIC_SEVERITY_WEIGHTS = {
        'initial-access': 1.2,
        'execution': 1.1,
        'persistence': 1.3,
        'privilege-escalation': 1.4,
        'defense-evasion': 1.2,
        'credential-access': 1.5,
        'discovery': 1.0,
        'lateral-movement': 1.3,
        'collection': 1.2,
        'command-and-control': 1.3,
        'exfiltration': 1.5,
        'impact': 1.6,
        'reconnaissance': 0.8,
        'resource-development': 0.9,
    }
    
    # Tactic to display name mapping
    TACTIC_NAMES = {
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
        'impact': 'Impact',
    }
    
    def __init__(self):
        # Will be loaded from MITRE data files
        self.technique_to_tactics: Dict[str, List[str]] = {}
        self.technique_names: Dict[str, str] = {}
        self._load_mitre_data()
    
    def _load_mitre_data(self):
        """Load MITRE ATT&CK technique and tactic mappings"""
        try:
            # Try to load from CSV files
            import os
            mitre_data_path = os.path.join(os.path.dirname(__file__), '../../mitre-attack/.data')
            
            tactics_file = os.path.join(mitre_data_path, 'tactics.csv')
            parent_file = os.path.join(mitre_data_path, 'parent.csv')
            
            if os.path.exists(tactics_file):
                tactics_df = pd.read_csv(tactics_file)
                for _, row in tactics_df.iterrows():
                    technique_id = row['technique_id']
                    tactic = row['tactic'].lower().replace(' ', '-')
                    if technique_id not in self.technique_to_tactics:
                        self.technique_to_tactics[technique_id] = []
                    if tactic not in self.technique_to_tactics[technique_id]:
                        self.technique_to_tactics[technique_id].append(tactic)
            
            if os.path.exists(parent_file):
                parent_df = pd.read_csv(parent_file)
                for _, row in parent_df.iterrows():
                    self.technique_names[row['technique_id']] = row['name']
        except Exception as e:
            print(f"Warning: Could not load MITRE data: {e}")
            print("Risk classification will work with technique IDs only")
    
    def classify_attack_by_tactic(self, attack: Attack) -> List[str]:
        """Classify an attack into MITRE tactics based on technique ID"""
        technique_id = attack.technique_id
        
        # Check if we have tactic mapping for this technique
        if technique_id in self.technique_to_tactics:
            return self.technique_to_tactics[technique_id]
        
        # Fallback: Infer from technique ID prefix (not ideal, but works)
        # This is a heuristic - real mapping should come from MITRE data
        tactics = []
        technique_lower = technique_id.lower()
        
        # Common MITRE technique ID patterns
        if any(t in technique_lower for t in ['t1552', 't1555', 't1110', 't1078']):  # Credential Access
            tactics.append('credential-access')
        elif any(t in technique_lower for t in ['t1190', 't1071', 't1133']):  # Initial Access
            tactics.append('initial-access')
        elif any(t in technique_lower for t in ['t1059', 't1106']):  # Execution
            tactics.append('execution')
        elif any(t in technique_lower for t in ['t1543', 't1037']):  # Persistence
            tactics.append('persistence')
        elif any(t in technique_lower for t in ['t1068', 't1055']):  # Privilege Escalation
            tactics.append('privilege-escalation')
        elif any(t in technique_lower for t in ['t1562', 't1070']):  # Defense Evasion
            tactics.append('defense-evasion')
        elif any(t in technique_lower for t in ['t1018', 't1082']):  # Discovery
            tactics.append('discovery')
        elif any(t in technique_lower for t in ['t1021', 't1072']):  # Lateral Movement
            tactics.append('lateral-movement')
        elif any(t in technique_lower for t in ['t1005', 't1039']):  # Collection
            tactics.append('collection')
        elif any(t in technique_lower for t in ['t1071', 't1095']):  # Command and Control
            tactics.append('command-and-control')
        elif any(t in technique_lower for t in ['t1041', 't1020']):  # Exfiltration
            tactics.append('exfiltration')
        elif any(t in technique_lower for t in ['t1485', 't1490']):  # Impact
            tactics.append('impact')
        
        return tactics if tactics else ['unknown']
    
    def assess_tactic_risk(self, attacks: List[Attack], tactic: str) -> MitreTacticRisk:
        """Assess risk for a specific MITRE tactic"""
        # Filter attacks by tactic
        tactic_attacks = []
        for attack in attacks:
            attack_tactics = self.classify_attack_by_tactic(attack)
            if tactic in attack_tactics:
                tactic_attacks.append(attack)
        
        if not tactic_attacks:
            return MitreTacticRisk(
                tactic_id=tactic,
                tactic_name=self.TACTIC_NAMES.get(tactic, tactic.title()),
                risk_score=0.0,
                attack_count=0,
                successful_count=0,
                unique_techniques=0,
                exposure_score=0.0,
                trend='stable',
                trend_score=0.5
            )
        
        # Calculate metrics
        attack_count = len(tactic_attacks)
        successful_count = sum(1 for a in tactic_attacks if a.success)
        success_rate = successful_count / attack_count if attack_count > 0 else 0
        
        unique_techniques = len(set(a.technique_id for a in tactic_attacks))
        
        # Calculate exposure score (0-100)
        exposure_score = min(
            (attack_count / 50.0) * 40 +  # Attack frequency (40%)
            (success_rate * 30) +  # Success rate (30%)
            (min(unique_techniques / 10.0, 1.0) * 30),  # Technique diversity (30%)
            100.0
        )
        
        # Calculate trend
        now = datetime.now(timezone.utc)
        recent_24h = [a for a in tactic_attacks 
                     if (now - (a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp)).total_seconds() < 86400]
        recent_7d = [a for a in tactic_attacks 
                    if (now - (a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp)).days <= 7]
        
        trend_score = 0.5
        trend = 'stable'
        
        if len(recent_7d) > 3:
            last_3d = [a for a in recent_7d 
                      if (now - (a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp)).days <= 3]
            prev_4d = [a for a in recent_7d 
                      if 3 < (now - (a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp)).days <= 7]
            
            if len(prev_4d) > 0:
                recent_rate = len(last_3d) / 3.0
                prev_rate = len(prev_4d) / 4.0
                if prev_rate > 0:
                    trend_ratio = recent_rate / prev_rate
                    if trend_ratio > 1.3:
                        trend = 'increasing'
                        trend_score = 1.0
                    elif trend_ratio > 1.1:
                        trend = 'increasing'
                        trend_score = 0.75
                    elif trend_ratio < 0.7:
                        trend = 'decreasing'
                        trend_score = 0.25
        
        # Calculate risk score with tactic severity weighting
        severity_weight = self.TACTIC_SEVERITY_WEIGHTS.get(tactic, 1.0)
        
        base_risk = (
            (attack_count / 100.0) * 30 +  # Volume (30%)
            (success_rate * 30) +  # Success (30%)
            (min(unique_techniques / 5.0, 1.0) * 20) +  # Diversity (20%)
            (trend_score * 20)  # Trend (20%)
        )
        
        risk_score = min(base_risk * severity_weight, 100.0)
        
        # Get technique details
        technique_counts = defaultdict(int)
        technique_success = defaultdict(int)
        for attack in tactic_attacks:
            technique_counts[attack.technique_id] += 1
            if attack.success:
                technique_success[attack.technique_id] += 1
        
        techniques = []
        for tech_id, count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            techniques.append({
                'technique_id': tech_id,
                'technique_name': self.technique_names.get(tech_id, tech_id),
                'attack_count': count,
                'successful_count': technique_success[tech_id],
                'success_rate': technique_success[tech_id] / count if count > 0 else 0
            })
        
        return MitreTacticRisk(
            tactic_id=tactic,
            tactic_name=self.TACTIC_NAMES.get(tactic, tactic.title()),
            risk_score=risk_score,
            attack_count=attack_count,
            successful_count=successful_count,
            unique_techniques=unique_techniques,
            exposure_score=exposure_score,
            trend=trend,
            trend_score=trend_score,
            techniques=techniques
        )
    
    def assess_technique_risk(self, attacks: List[Attack], technique_id: str) -> MitreTechniqueRisk:
        """Assess risk for a specific MITRE technique"""
        technique_attacks = [a for a in attacks if a.technique_id == technique_id]
        
        if not technique_attacks:
            return MitreTechniqueRisk(
                technique_id=technique_id,
                technique_name=self.technique_names.get(technique_id, technique_id),
                risk_score=0.0,
                attack_count=0,
                successful_count=0,
                success_rate=0.0,
                recent_activity=0,
                trend='stable',
                tactics=self.technique_to_tactics.get(technique_id, [])
            )
        
        attack_count = len(technique_attacks)
        successful_count = sum(1 for a in technique_attacks if a.success)
        success_rate = successful_count / attack_count if attack_count > 0 else 0
        
        # Recent activity (last 24h)
        now = datetime.now(timezone.utc)
        recent_24h = sum(1 for a in technique_attacks 
                        if (now - (a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp)).total_seconds() < 86400)
        
        # Calculate trend
        recent_7d = [a for a in technique_attacks 
                    if (now - (a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp)).days <= 7]
        
        trend = 'stable'
        if len(recent_7d) > 2:
            last_3d = len([a for a in recent_7d 
                          if (now - (a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp)).days <= 3])
            if last_3d > len(recent_7d) * 0.6:
                trend = 'increasing'
            elif last_3d < len(recent_7d) * 0.3:
                trend = 'decreasing'
        
        # Risk score
        risk_score = min(
            (attack_count / 50.0) * 40 +
            (success_rate * 40) +
            (min(recent_24h / 10.0, 1.0) * 20),
            100.0
        )
        
        return MitreTechniqueRisk(
            technique_id=technique_id,
            technique_name=self.technique_names.get(technique_id, technique_id),
            risk_score=risk_score,
            attack_count=attack_count,
            successful_count=successful_count,
            success_rate=success_rate,
            recent_activity=recent_24h,
            trend=trend,
            tactics=self.technique_to_tactics.get(technique_id, []),
            severity_multiplier=1.0
        )
    
    def generate_risk_portfolio(self, attacks: List[Attack]) -> Dict[str, MitreTacticRisk]:
        """Generate comprehensive risk portfolio across all MITRE tactics"""
        portfolio = {}
        
        # Assess risk for each tactic
        for tactic in self.TACTIC_NAMES.keys():
            portfolio[tactic] = self.assess_tactic_risk(attacks, tactic)
        
        return portfolio
    
    def project_risk(self, attacks: List[Attack], time_horizon: str = '7d') -> RiskProjection:
        """Project risk for future time period"""
        if not attacks:
            return RiskProjection(
                time_horizon=time_horizon,
                predicted_attacks=0,
                predicted_techniques=0,
                predicted_tactics=0,
                high_risk_tactics=[],
                high_risk_techniques=[],
                confidence=0.0,
                risk_trajectory=[]
            )
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame([{
            'timestamp': a.timestamp,
            'technique_id': a.technique_id,
            'success': 1 if a.success else 0
        } for a in attacks])
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        # Determine hours for projection
        hours_map = {'24h': 24, '7d': 168, '30d': 720}
        hours = hours_map.get(time_horizon, 168)
        
        # Group by hour for time series analysis
        df['hour'] = df['timestamp'].dt.floor('H')
        hourly = df.groupby('hour').agg({
            'technique_id': ['count', 'nunique'],
            'success': 'sum'
        }).reset_index()
        
        hourly.columns = ['hour', 'attack_count', 'unique_techniques', 'successful']
        
        if len(hourly) < 3:
            # Not enough data for regression
            avg_attacks = df.shape[0] / max((df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600, 1)
            predicted_attacks = int(avg_attacks * hours)
            predicted_techniques = len(df['technique_id'].unique())
            predicted_tactics = len(set().union(*[self.classify_attack_by_tactic(Attack(**{**a, 'technique_id': a['technique_id']})) 
                                                 for a in df.to_dict('records')]))
            
            return RiskProjection(
                time_horizon=time_horizon,
                predicted_attacks=predicted_attacks,
                predicted_techniques=predicted_techniques,
                predicted_tactics=predicted_tactics,
                high_risk_tactics=[],
                high_risk_techniques=[],
                confidence=0.3,
                risk_trajectory=[]
            )
        
        # Linear regression for attack count projection
        hourly['hours_since_start'] = (hourly['hour'] - hourly['hour'].min()).dt.total_seconds() / 3600
        
        X = hourly['hours_since_start'].values.reshape(-1, 1)
        y_attacks = hourly['attack_count'].values
        
        model = LinearRegression()
        model.fit(X, y_attacks)
        
        last_hour = hourly['hours_since_start'].max()
        future_hours = np.arange(last_hour + 1, last_hour + hours + 1).reshape(-1, 1)
        predicted_attacks_hourly = model.predict(future_hours)
        predicted_attacks_hourly = np.maximum(predicted_attacks_hourly, 0)
        
        predicted_attacks = int(np.sum(predicted_attacks_hourly))
        
        # Predict techniques and tactics
        unique_techniques = df['technique_id'].nunique()
        all_tactics = set()
        for _, row in df.iterrows():
            tactics = self.classify_attack_by_tactic(
                Attack(id="", timestamp=row['timestamp'], website_url="", 
                      vulnerability_type="", technique_id=row['technique_id'], 
                      success=bool(row['success']), source_ip="", session_id="")
            )
            all_tactics.update(tactics)
        
        predicted_techniques = unique_techniques
        predicted_tactics = len(all_tactics)
        
        # Identify high-risk tactics and techniques
        portfolio = self.generate_risk_portfolio(attacks)
        high_risk_tactics = [t for t, risk in portfolio.items() if risk.risk_score > 50]
        
        technique_risks = {}
        for tech_id in df['technique_id'].unique():
            tech_risk = self.assess_technique_risk(attacks, tech_id)
            technique_risks[tech_id] = tech_risk
        
        high_risk_techniques = [tech_id for tech_id, risk in technique_risks.items() if risk.risk_score > 50]
        
        # Calculate confidence
        r2 = model.score(X, y_attacks)
        confidence = min(r2 * 0.7 + (len(hourly) / 100.0) * 0.3, 1.0)
        
        # Generate trajectory
        trajectory = []
        for i, hour in enumerate(future_hours[:min(30, len(future_hours))]):  # First 30 predictions
            trajectory.append({
                'timestamp': (hourly['hour'].max() + timedelta(hours=i+1)).isoformat(),
                'predicted_attacks': max(0, int(predicted_attacks_hourly[i]))
            })
        
        return RiskProjection(
            time_horizon=time_horizon,
            predicted_attacks=predicted_attacks,
            predicted_techniques=predicted_techniques,
            predicted_tactics=predicted_tactics,
            high_risk_tactics=high_risk_tactics[:10],
            high_risk_techniques=high_risk_techniques[:10],
            confidence=confidence,
            risk_trajectory=trajectory
        )

