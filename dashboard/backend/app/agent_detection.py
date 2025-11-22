"""Autonomous AI agent detection logic"""
from app.models import Attack
from app.schemas import AgentIndicators
from app.database import supabase
from datetime import datetime, timedelta
from typing import List
import statistics


class AgentDetector:
    """Detect autonomous AI agent indicators in attacks"""
    
    def analyze_attack(self, attack: Attack) -> AgentIndicators:
        """Analyze a single attack for autonomous agent indicators"""
        indicators = []
        
        try:
            # Get recent attacks from same source (last 5 minutes)
            recent_window = attack.timestamp - timedelta(minutes=5)
            
            # Query Supabase for recent attacks from same source
            # Format timestamps for Supabase query
            window_str = recent_window.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            timestamp_str = attack.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            
            response = supabase.table("vulnerability_logs")\
                .select("*")\
                .eq("attacker_id", attack.source_ip)\
                .gte("timestamp", window_str)\
                .lte("timestamp", timestamp_str)\
                .order("timestamp")\
                .execute()
            
            recent_logs = response.data if response.data else []
            
            # Convert to Attack objects
            recent_attacks = []
            for log in recent_logs:
                try:
                    recent_attacks.append(Attack.from_vulnerability_log(log))
                except Exception as e:
                    print(f"Error converting log to attack: {e}")
                    continue
            
            # Speed analysis: rapid successive attacks
            speed_score = 0.0
            if len(recent_attacks) > 1:
                time_diffs = []
                for i in range(1, len(recent_attacks)):
                    diff = (recent_attacks[i].timestamp - recent_attacks[i-1].timestamp).total_seconds()
                    time_diffs.append(diff)
                
                if time_diffs:
                    avg_time = statistics.mean(time_diffs)
                    # Very fast attacks (< 1 second) suggest automation
                    if avg_time < 1.0:
                        speed_score = 1.0
                        indicators.append("Extremely rapid attack sequence")
                    elif avg_time < 5.0:
                        speed_score = 0.7
                        indicators.append("Rapid attack sequence")
                    elif avg_time < 30.0:
                        speed_score = 0.4
                        indicators.append("Fast attack sequence")
            
            # Pattern analysis: systematic exploration
            pattern_score = 0.0
            if len(recent_attacks) > 2:
                # Check for systematic vulnerability testing
                vuln_types = [a.vulnerability_type for a in recent_attacks]
                unique_vulns = len(set(vuln_types))
                total_attacks = len(vuln_types)
                
                # High diversity in short time suggests systematic scanning
                if unique_vulns / total_attacks > 0.7 and total_attacks > 3:
                    pattern_score = 0.8
                    indicators.append("Systematic vulnerability exploration")
                
                # Check for methodical website targeting
                websites = [a.website_url for a in recent_attacks]
                if len(set(websites)) > 1:
                    pattern_score = max(pattern_score, 0.6)
                    indicators.append("Multi-target systematic approach")
            
            # Coordination analysis: multiple IPs, similar patterns
            coordination_score = 0.0
            # Check for similar attack patterns from different IPs in short time
            similar_response = supabase.table("vulnerability_logs")\
                .select("*")\
                .eq("vulnerability_type", attack.vulnerability_type)\
                .eq("technique_id", attack.technique_id)\
                .gte("timestamp", window_str)\
                .lte("timestamp", timestamp_str)\
                .execute()
            
            similar_logs = similar_response.data if similar_response.data else []
            unique_ips = len(set([log.get("attacker_id") for log in similar_logs if log.get("attacker_id")]))
            
            if unique_ips > 3:
                coordination_score = 0.7
                indicators.append("Coordinated multi-source attack pattern")
            elif unique_ips > 1:
                coordination_score = 0.4
                indicators.append("Multiple sources with similar patterns")
            
            # Overall probability (weighted combination)
            overall = (speed_score * 0.3 + pattern_score * 0.4 + coordination_score * 0.3)
            
            if overall > 0.7:
                indicators.append("High probability of autonomous agent")
            elif overall > 0.4:
                indicators.append("Moderate probability of autonomous agent")
            
            return AgentIndicators(
                speed_score=speed_score,
                pattern_score=pattern_score,
                coordination_score=coordination_score,
                overall_agent_probability=overall,
                indicators=indicators if indicators else ["No strong agent indicators"]
            )
            
        except Exception as e:
            print(f"Error in agent detection: {e}")
            return AgentIndicators(
                speed_score=0.0,
                pattern_score=0.0,
                coordination_score=0.0,
                overall_agent_probability=0.0,
                indicators=["Error analyzing attack"]
            )

