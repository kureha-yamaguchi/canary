"""FastAPI main application"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pathlib import Path
from contextlib import asynccontextmanager
import uvicorn
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import json
from datetime import datetime, timedelta
import asyncio

from app.database import supabase
from app.models import Attack
from app.schemas import (
    AttackResponse, 
    StatsResponse, 
    RiskForecast,
    RiskPortfolioResponse,
    MitreTacticRiskResponse,
    RiskProjectionResponse,
    AdvancedRiskForecastResponse,
    RiskScoreBreakdown
)
from app.forecasting import RiskForecaster
# Temporarily disable agent detection to focus on basic views
# from app.agent_detection import AgentDetector

# Trajectory analysis imports
from app.trajectory_schemas import (
    HoneypotEventSchema,
    RedTeamTrajectorySchema,
    ExternalTrajectorySchema,
    TrajectoryPredictionsSchema,
    TrajectoryComparisonSchema,
    VulnerabilityRecommendationsSchema,
    HoneypotVulnerabilitySchema,
    ClassifierModelInfoSchema,
    ClassifyTrajectoryRequest,
    ClassifyTrajectoryResponse,
    VulnerabilityListResponse,
    TrajectoryListResponse,
)
from app.trajectory_classifier import trajectory_classifier

# Global connections manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"Error broadcasting to connection: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected connections
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()
forecaster = RiskForecaster()

# Initialize MITRE risk engine lazily (may fail if dependencies missing)
try:
    from app.mitre_risk_engine import MitreRiskClassificationEngine
    mitre_risk_engine = MitreRiskClassificationEngine()
except Exception as e:
    print(f"Warning: Could not initialize MITRE risk engine: {e}")
    mitre_risk_engine = None

# agent_detector = AgentDetector()  # Disabled for now

# Background task for polling Supabase and broadcasting updates
polling_task = None

async def poll_and_broadcast():
    """Poll Supabase for new attacks and broadcast via WebSocket"""
    # Simplified: Just sleep for now, will re-enable polling once basic queries work
    while True:
        try:
            await asyncio.sleep(10)  # Sleep - polling disabled temporarily
        except Exception as e:
            print(f"Error in polling task: {e}")
            await asyncio.sleep(5)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global polling_task
    polling_task = asyncio.create_task(poll_and_broadcast())
    yield
    # Shutdown
    if polling_task:
        polling_task.cancel()
        try:
            await polling_task
        except asyncio.CancelledError:
            pass

app = FastAPI(
    title="AI Cyber Attack Monitoring Dashboard API",
    description="Real-time monitoring and risk forecasting for AI cyber attacks",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "AI Cyber Attack Monitoring API"}

@app.get("/api/mitre-campaigns-csv")
async def get_mitre_campaigns_csv():
    """Serve the MITRE campaigns CSV file"""
    try:
        # Look for CSV in dashboard/backend/data directory (primary location)
        csv_path = Path(__file__).parent.parent / "data" / "mitre_campaigns_full.csv"
        
        if not csv_path.exists():
            # Fallback: try other possible locations
            possible_paths = [
                Path(__file__).parent.parent.parent.parent / "mitre-attack-viz" / "public" / "mitre_campaigns_full.csv",
                Path(__file__).parent.parent.parent.parent / "data" / "mitre_campaigns_full.csv",
            ]
            
            for path in possible_paths:
                if path.exists():
                    csv_path = path
                    break
        
        if not csv_path.exists():
            raise HTTPException(
                status_code=404, 
                detail=f"MITRE campaigns CSV file not found at: {csv_path}"
            )
        
        return FileResponse(
            path=str(csv_path),
            media_type="text/csv",
            filename="mitre_campaigns_full.csv"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error serving CSV file: {str(e)}")

@app.get("/api/attacks", response_model=List[AttackResponse])
async def get_attacks(limit: int = 100, offset: int = 0, include_synthetic: bool = False):
    """Get recent attacks
    
    Args:
        limit: Maximum number of attacks to return
        offset: Number of attacks to skip
        include_synthetic: If False, exclude synthetic data (is_synthetic = TRUE)
    """
    try:
        query = supabase.table("vulnerability_logs")\
            .select("*")\
            .order("timestamp", desc=True)
        
        response = query.range(offset, offset + limit - 1).execute()
        
        if not response.data:
            return []
        
        # Filter synthetic data if requested
        filtered_data = response.data
        if not include_synthetic:
            filtered_data = [
                log for log in response.data 
                if log.get("is_synthetic") is None or log.get("is_synthetic") is False
            ]
        
        attacks = []
        for log_data in filtered_data:
            try:
                attack = Attack.from_vulnerability_log(log_data)
                # Skip agent detection for now - just return basic data
                # agent_indicators = agent_detector.analyze_attack(attack)
                agent_indicators = None
                
                attacks.append(AttackResponse(
                    id=attack.id,
                    timestamp=attack.timestamp,
                    website_url=attack.website_url,
                    vulnerability_type=attack.vulnerability_type,
                    attack_vector=attack.attack_vector,
                    technique_id=attack.technique_id,
                    success=attack.success,
                    payload=attack.payload,
                    source_ip=attack.source_ip,
                    user_agent=attack.user_agent,
                    response_code=attack.response_code,
                    session_id=attack.session_id,
                    agent_indicators=agent_indicators
                ))
            except Exception as e:
                print(f"Error converting log to attack response: {e}")
                continue
        
        return attacks
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats", response_model=StatsResponse)
async def get_stats(include_synthetic: bool = False):
    """Get comprehensive statistics
    
    Args:
        include_synthetic: If False, exclude synthetic data (is_synthetic = TRUE)
    """
    try:
        from datetime import timezone
        now = datetime.now(timezone.utc)
        
        # Get all attacks
        query = supabase.table("vulnerability_logs")\
            .select("*")
        
        all_response = query.execute()
        
        if not all_response.data:
            return StatsResponse(
                total_attacks=0,
                attacks_24h=0,
                attacks_7d=0,
                attacks_30d=0,
                successful_attacks=0,
                failed_attacks=0,
                websites_attacked=0,
                successful_vulnerabilities=[],
                failed_vulnerabilities=[],
                attack_vectors=[],
                website_stats=[],
                vulnerability_stats=[],
                time_series=[],
                technique_stats=[]
            )
        
        # Filter synthetic data if requested
        filtered_data = all_response.data
        if not include_synthetic:
            filtered_data = [
                log for log in filtered_data 
                if log.get("is_synthetic") is None or log.get("is_synthetic") is False
            ]
        
        # Convert to Attack objects
        all_attacks = []
        for log_data in filtered_data:
            try:
                attack = Attack.from_vulnerability_log(log_data)
                # Ensure timestamp is timezone-aware
                if attack.timestamp.tzinfo is None:
                    attack.timestamp = attack.timestamp.replace(tzinfo=timezone.utc)
                all_attacks.append(attack)
            except Exception as e:
                print(f"Error converting log: {e}")
                continue
        
        # Time windows - normalize timestamps for comparison
        def normalize_datetime(dt):
            """Ensure datetime is timezone-aware"""
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        
        time_24h_ago = now - timedelta(hours=24)
        time_7d_ago = now - timedelta(days=7)
        time_30d_ago = now - timedelta(days=30)
        
        attacks_24h = [a for a in all_attacks if normalize_datetime(a.timestamp) >= time_24h_ago]
        attacks_7d = [a for a in all_attacks if normalize_datetime(a.timestamp) >= time_7d_ago]
        attacks_30d = [a for a in all_attacks if normalize_datetime(a.timestamp) >= time_30d_ago]
        
        # Successful vs failed
        successful_attacks = [a for a in all_attacks if a.success]
        failed_attacks = [a for a in all_attacks if not a.success]
        
        # Websites attacked
        websites_attacked = len(set(a.website_url for a in all_attacks))
        
        # Vulnerabilities
        successful_vulns = set(a.vulnerability_type for a in successful_attacks)
        failed_vulns = set(a.vulnerability_type for a in failed_attacks)
        
        # Attack vectors (derived from vulnerability types)
        attack_vector_counts: Dict[str, int] = {}
        for attack in all_attacks:
            vector = attack.attack_vector or attack.vulnerability_type
            attack_vector_counts[vector] = attack_vector_counts.get(vector, 0) + 1
        
        attack_vectors = [{"vector": k, "count": v} for k, v in attack_vector_counts.items()]
        
        # Website stats
        website_counts: Dict[str, Dict[str, int]] = {}
        for attack in all_attacks:
            if attack.website_url not in website_counts:
                website_counts[attack.website_url] = {"total": 0, "successful": 0}
            website_counts[attack.website_url]["total"] += 1
            if attack.success:
                website_counts[attack.website_url]["successful"] += 1
        
        website_stats = [{"url": k, "total": v["total"], "successful": v["successful"]} 
                        for k, v in website_counts.items()]
        
        # Vulnerability stats
        vuln_counts: Dict[str, Dict[str, int]] = {}
        for attack in all_attacks:
            if attack.vulnerability_type not in vuln_counts:
                vuln_counts[attack.vulnerability_type] = {"total": 0, "successful": 0}
            vuln_counts[attack.vulnerability_type]["total"] += 1
            if attack.success:
                vuln_counts[attack.vulnerability_type]["successful"] += 1
        
        vulnerability_stats = [{"type": k, "total": v["total"], "successful": v["successful"]} 
                              for k, v in vuln_counts.items()]
        
        # Technique stats
        technique_counts: Dict[str, Dict[str, int]] = {}
        for attack in all_attacks:
            if attack.technique_id not in technique_counts:
                technique_counts[attack.technique_id] = {"total": 0, "successful": 0}
            technique_counts[attack.technique_id]["total"] += 1
            if attack.success:
                technique_counts[attack.technique_id]["successful"] += 1
        
        technique_stats = [{"technique_id": k, "total": v["total"], "successful": v["successful"]} 
                          for k, v in technique_counts.items()]
        
        # Time series (last 24 hours, hourly buckets)
        time_series = []
        def normalize_datetime(dt):
            """Ensure datetime is timezone-aware"""
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        
        for i in range(24):
            hour_start = now - timedelta(hours=i+1)
            hour_end = now - timedelta(hours=i)
            hour_attacks = [a for a in all_attacks 
                          if hour_start <= normalize_datetime(a.timestamp) < hour_end]
            time_series.append({
                "timestamp": hour_start.isoformat(),
                "count": len(hour_attacks)
            })
        time_series.reverse()
        
        return StatsResponse(
            total_attacks=len(all_attacks),
            attacks_24h=len(attacks_24h),
            attacks_7d=len(attacks_7d),
            attacks_30d=len(attacks_30d),
            successful_attacks=len(successful_attacks),
            failed_attacks=len(failed_attacks),
            websites_attacked=websites_attacked,
            successful_vulnerabilities=list(successful_vulns),
            failed_vulnerabilities=list(failed_vulns),
            attack_vectors=attack_vectors,
            website_stats=website_stats,
            vulnerability_stats=vulnerability_stats,
            time_series=time_series,
            technique_stats=technique_stats
        )
    except Exception as e:
        print(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/risk-forecast", response_model=RiskForecast)
async def get_risk_forecast(include_synthetic: bool = False):
    """Get risk trajectory and forecasting - simplified for now
    
    Args:
        include_synthetic: If False, exclude synthetic data (is_synthetic = TRUE)
    """
    try:
        # Temporarily return empty forecast - will implement later
        return forecaster._empty_forecast()
    except Exception as e:
        print(f"Error getting forecast: {e}")
        # Return empty forecast on error
        return forecaster._empty_forecast()

@app.get("/api/advanced-risk-forecast", response_model=AdvancedRiskForecastResponse)
async def get_advanced_risk_forecast(include_synthetic: bool = False):
    """Get advanced risk forecast with full statistical analysis and transparency
    
    Args:
        include_synthetic: If False, exclude synthetic data (is_synthetic = TRUE)
    """
    try:
        from app.advanced_forecasting import AdvancedRiskForecaster
        from datetime import timezone
        
        advanced_forecaster = AdvancedRiskForecaster()
        
        # Get all attacks
        all_response = supabase.table("vulnerability_logs")\
            .select("*")\
            .execute()
        
        if not all_response.data:
            return AdvancedRiskForecastResponse(
                risk_score=0.0,
                risk_score_breakdown=RiskScoreBreakdown(
                    attack_frequency={},
                    success_rate={},
                    vulnerability_diversity={},
                    trend_momentum={},
                    methodology={},
                    data_quality={"sufficient": False}
                ),
                projection_24h={},
                projection_7d={},
                projection_30d={},
                methodology={},
                statistical_analysis={},
                data_quality_assessment={}
            )
        
        # Filter synthetic data if requested
        filtered_data = all_response.data
        if not include_synthetic:
            filtered_data = [
                log for log in all_response.data 
                if log.get("is_synthetic") is None or log.get("is_synthetic") is False
            ]
        
        # Convert to Attack objects
        all_attacks = []
        for log_data in filtered_data:
            try:
                attack = Attack.from_vulnerability_log(log_data)
                if attack.timestamp.tzinfo is None:
                    attack.timestamp = attack.timestamp.replace(tzinfo=timezone.utc)
                all_attacks.append(attack)
            except Exception as e:
                print(f"Error converting log: {e}")
                continue
        
        # Calculate risk score with breakdown
        risk_analysis = advanced_forecaster.calculate_risk_score(all_attacks, time_window_days=7)
        
        # Generate projections
        projection_24h = advanced_forecaster.project_attacks(all_attacks, time_horizon_hours=24, method="ensemble")
        projection_7d = advanced_forecaster.project_attacks(all_attacks, time_horizon_hours=168, method="ensemble")
        projection_30d = advanced_forecaster.project_attacks(all_attacks, time_horizon_hours=720, method="ensemble")
        
        # Statistical analysis summary
        import pandas as pd
        if all_attacks:
            df = pd.DataFrame([{
                'timestamp': a.timestamp,
                'success': 1 if a.success else 0,
                'technique_id': a.technique_id
            } for a in all_attacks])
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            now = datetime.now(timezone.utc)
            recent_7d = df[df['timestamp'] >= (now - timedelta(days=7))]
            
            import numpy as np
            daily_counts = recent_7d.groupby(recent_7d['timestamp'].dt.date).size()
            mean_attacks = float(daily_counts.mean()) if len(daily_counts) > 0 else 0.0
            std_attacks = float(daily_counts.std()) if len(daily_counts) > 1 else 0.0
            success_rate = float(recent_7d['success'].mean()) if len(recent_7d) > 0 else 0.0
            time_span = float((df['timestamp'].max() - df['timestamp'].min()).days) if len(df) > 1 else 0.0
            
            # Replace NaN/Inf with valid numbers
            if np.isnan(mean_attacks) or np.isinf(mean_attacks):
                mean_attacks = 0.0
            if np.isnan(std_attacks) or np.isinf(std_attacks):
                std_attacks = 0.0
            if np.isnan(success_rate) or np.isinf(success_rate):
                success_rate = 0.0
            if np.isnan(time_span) or np.isinf(time_span):
                time_span = 0.0
            
            statistical_analysis = {
                "total_attacks": len(all_attacks),
                "recent_7d_attacks": len(recent_7d),
                "mean_attacks_per_day": mean_attacks,
                "std_attacks_per_day": std_attacks,
                "success_rate": success_rate,
                "unique_techniques": int(df['technique_id'].nunique()),
                "time_span_days": time_span
            }
        else:
            statistical_analysis = {}
        
        # Build risk_score_breakdown by flattening components
        components = risk_analysis.get("components", {}) or {}
        breakdown_dict = {
            "attack_frequency": components.get("attack_frequency") or {},
            "success_rate": components.get("success_rate") or {},
            "vulnerability_diversity": components.get("vulnerability_diversity") or {},
            "trend_momentum": components.get("trend_momentum") or {},
            "methodology": risk_analysis.get("methodology") or {},
            "data_quality": risk_analysis.get("data_quality") or {}
        }
        
        # Ensure all dict values are JSON serializable (convert any non-serializable types)
        import json
        try:
            # Test if the breakdown can be serialized
            json.dumps(breakdown_dict)
        except (TypeError, ValueError) as e:
            print(f"Serialization error in breakdown_dict: {e}")
            # Provide empty defaults if there's a serialization issue
            breakdown_dict = {
                "attack_frequency": {},
                "success_rate": {},
                "vulnerability_diversity": {},
                "trend_momentum": {},
                "methodology": {},
                "data_quality": {"sufficient": False, "error": str(e)}
            }
        
        try:
            breakdown = RiskScoreBreakdown(**breakdown_dict)
        except Exception as e:
            print(f"Error creating RiskScoreBreakdown: {e}")
            # Create a minimal breakdown
            breakdown = RiskScoreBreakdown(
                attack_frequency={},
                success_rate={},
                vulnerability_diversity={},
                trend_momentum={},
                methodology={},
                data_quality={"sufficient": False, "error": str(e)}
            )
        
        return AdvancedRiskForecastResponse(
            risk_score=risk_analysis.get("risk_score", 0.0),
            risk_score_breakdown=breakdown,
            projection_24h=projection_24h,
            projection_7d=projection_7d,
            projection_30d=projection_30d,
            methodology=advanced_forecaster.methodology or {},
            statistical_analysis=statistical_analysis,
            data_quality_assessment=risk_analysis.get("data_quality", {})
        )
    except Exception as e:
        print(f"Error getting advanced risk forecast: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/mitre-risk-portfolio", response_model=RiskPortfolioResponse)
async def get_mitre_risk_portfolio(include_synthetic: bool = False):
    """Get MITRE ATT&CK-based risk portfolio
    
    Args:
        include_synthetic: If False, exclude synthetic data (is_synthetic = TRUE)
    """
    try:
        if mitre_risk_engine is None:
            raise HTTPException(status_code=503, detail="MITRE risk engine not available")
        
        from datetime import timezone
        
        # Get all attacks
        all_response = supabase.table("vulnerability_logs")\
            .select("*")\
            .execute()
        
        if not all_response.data:
            return RiskPortfolioResponse(
                tactics=[],
                overall_risk_score=0.0,
                high_risk_tactics=[],
                moderate_risk_tactics=[],
                low_risk_tactics=[],
                risk_distribution={}
            )
        
        # Filter synthetic data if requested
        filtered_data = all_response.data
        if not include_synthetic:
            filtered_data = [
                log for log in all_response.data 
                if log.get("is_synthetic") is None or log.get("is_synthetic") is False
            ]
        
        # Convert to Attack objects
        all_attacks = []
        for log_data in filtered_data:
            try:
                attack = Attack.from_vulnerability_log(log_data)
                if attack.timestamp.tzinfo is None:
                    attack.timestamp = attack.timestamp.replace(tzinfo=timezone.utc)
                all_attacks.append(attack)
            except Exception as e:
                print(f"Error converting log: {e}")
                continue
        
        # Generate risk portfolio
        portfolio = mitre_risk_engine.generate_risk_portfolio(all_attacks)
        
        # Convert to response format
        tactic_risks = []
        high_risk = []
        moderate_risk = []
        low_risk = []
        risk_distribution = {}
        
        overall_risk = 0.0
        
        for tactic_id, risk in portfolio.items():
            if risk.attack_count > 0:  # Only include tactics with attacks
                tactic_risks.append(MitreTacticRiskResponse(
                    tactic_id=risk.tactic_id,
                    tactic_name=risk.tactic_name,
                    risk_score=risk.risk_score,
                    attack_count=risk.attack_count,
                    successful_count=risk.successful_count,
                    unique_techniques=risk.unique_techniques,
                    exposure_score=risk.exposure_score,
                    trend=risk.trend,
                    trend_score=risk.trend_score,
                    techniques=risk.techniques
                ))
                
                risk_distribution[risk.tactic_id] = risk.risk_score
                overall_risk = max(overall_risk, risk.risk_score)
                
                # Categorize by risk level
                if risk.risk_score >= 70:
                    high_risk.append(risk.tactic_id)
                elif risk.risk_score >= 40:
                    moderate_risk.append(risk.tactic_id)
                else:
                    low_risk.append(risk.tactic_id)
        
        # Sort by risk score (highest first)
        tactic_risks.sort(key=lambda x: x.risk_score, reverse=True)
        
        return RiskPortfolioResponse(
            tactics=tactic_risks,
            overall_risk_score=overall_risk,
            high_risk_tactics=high_risk,
            moderate_risk_tactics=moderate_risk,
            low_risk_tactics=low_risk,
            risk_distribution=risk_distribution
        )
    except Exception as e:
        print(f"Error getting MITRE risk portfolio: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/mitre-risk-projection", response_model=RiskProjectionResponse)
async def get_mitre_risk_projection(time_horizon: str = "7d", include_synthetic: bool = False):
    """Get MITRE ATT&CK-based risk projection
    
    Args:
        time_horizon: Prediction window ('24h', '7d', '30d')
        include_synthetic: If False, exclude synthetic data (is_synthetic = TRUE)
    """
    try:
        if mitre_risk_engine is None:
            raise HTTPException(status_code=503, detail="MITRE risk engine not available")
        
        from datetime import timezone
        
        if time_horizon not in ["24h", "7d", "30d"]:
            time_horizon = "7d"
        
        # Get all attacks
        all_response = supabase.table("vulnerability_logs")\
            .select("*")\
            .execute()
        
        if not all_response.data:
            return RiskProjectionResponse(
                time_horizon=time_horizon,
                predicted_attacks=0,
                predicted_techniques=0,
                predicted_tactics=0,
                high_risk_tactics=[],
                high_risk_techniques=[],
                confidence=0.0,
                risk_trajectory=[],
                tactic_projections={}
            )
        
        # Filter synthetic data if requested
        filtered_data = all_response.data
        if not include_synthetic:
            filtered_data = [
                log for log in all_response.data 
                if log.get("is_synthetic") is None or log.get("is_synthetic") is False
            ]
        
        # Convert to Attack objects
        all_attacks = []
        for log_data in filtered_data:
            try:
                attack = Attack.from_vulnerability_log(log_data)
                if attack.timestamp.tzinfo is None:
                    attack.timestamp = attack.timestamp.replace(tzinfo=timezone.utc)
                all_attacks.append(attack)
            except Exception as e:
                print(f"Error converting log: {e}")
                continue
        
        # Generate projection
        projection = mitre_risk_engine.project_risk(all_attacks, time_horizon)
        
        # Generate tactic-specific projections
        tactic_projections = {}
        portfolio = mitre_risk_engine.generate_risk_portfolio(all_attacks)
        
        for tactic_id, risk in portfolio.items():
            if risk.attack_count > 0:
                # Simple projection based on trend
                if risk.trend == 'increasing':
                    projected_attacks = int(risk.attack_count * 1.2 * (168 / 24 if time_horizon == "7d" else 1))
                elif risk.trend == 'decreasing':
                    projected_attacks = int(risk.attack_count * 0.8 * (168 / 24 if time_horizon == "7d" else 1))
                else:
                    projected_attacks = int(risk.attack_count * 1.0 * (168 / 24 if time_horizon == "7d" else 1))
                
                tactic_projections[tactic_id] = {
                    "predicted_attacks": projected_attacks,
                    "current_risk_score": risk.risk_score,
                    "trend": risk.trend
                }
        
        return RiskProjectionResponse(
            time_horizon=projection.time_horizon,
            predicted_attacks=projection.predicted_attacks,
            predicted_techniques=projection.predicted_techniques,
            predicted_tactics=projection.predicted_tactics,
            high_risk_tactics=projection.high_risk_tactics,
            high_risk_techniques=projection.high_risk_techniques,
            confidence=projection.confidence,
            risk_trajectory=projection.risk_trajectory,
            tactic_projections=tactic_projections
        )
    except Exception as e:
        print(f"Error getting MITRE risk projection: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# Trajectory Analysis API Endpoints
# ============================================

@app.get("/api/vulnerabilities", response_model=VulnerabilityListResponse)
async def get_vulnerabilities():
    """Get list of honeypot vulnerabilities with statistics"""
    # For MVP, return mock data representing available honeypot vulnerabilities
    # In production, this would come from database
    mock_vulnerabilities = [
        HoneypotVulnerabilitySchema(
            id="vuln-sql-001",
            name="SQL Injection - User Login",
            type="sql_injection",
            endpoint="/api/login",
            description="SQL injection vulnerability in the login endpoint authentication query",
            expected_ttps=["T1190", "T1059", "T1005"],
            stats={
                "total_attempts": 156,
                "successful_attempts": 34,
                "red_team_trajectories": 12,
                "external_trajectories": 144,
                "avg_steps_to_exploit": 4.2,
                "avg_time_to_exploit_seconds": 45.8
            },
            risk_level="high",
            recommendations={
                "vulnerability_id": "vuln-sql-001",
                "vulnerability_type": "sql_injection",
                "detection_rules": [
                    {
                        "id": "dr-001",
                        "title": "SQL Syntax in Parameters",
                        "description": "Alert on SQL keywords (SELECT, UNION, DROP) in request parameters",
                        "related_techniques": ["T1190"],
                        "priority": "high"
                    },
                    {
                        "id": "dr-002",
                        "title": "Rapid Sequential Requests",
                        "description": "Alert on >5 requests to same endpoint within 10 seconds",
                        "related_techniques": ["T1595"],
                        "priority": "medium"
                    }
                ],
                "early_warning_patterns": [
                    {
                        "pattern": "Quote testing",
                        "description": "Single quote injection attempts indicate SQL probing",
                        "typical_step": 2,
                        "detection_window_seconds": 30
                    },
                    {
                        "pattern": "Error-based enumeration",
                        "description": "Sequential requests causing 500 errors suggest blind injection attempts",
                        "typical_step": 3,
                        "detection_window_seconds": 60
                    }
                ],
                "mitigations": [
                    {
                        "title": "Use Parameterized Queries",
                        "description": "Replace string concatenation with prepared statements",
                        "blocks_techniques": ["T1190"],
                        "implementation_effort": "medium"
                    },
                    {
                        "title": "Input Validation",
                        "description": "Implement allowlist validation for all user inputs",
                        "blocks_techniques": ["T1190", "T1059"],
                        "implementation_effort": "low"
                    }
                ]
            }
        ),
        HoneypotVulnerabilitySchema(
            id="vuln-xss-001",
            name="XSS - Comment Field",
            type="xss",
            endpoint="/api/comments",
            description="Reflected XSS vulnerability in the comment submission form",
            expected_ttps=["T1190", "T1185", "T1539"],
            stats={
                "total_attempts": 89,
                "successful_attempts": 23,
                "red_team_trajectories": 8,
                "external_trajectories": 81,
                "avg_steps_to_exploit": 3.1,
                "avg_time_to_exploit_seconds": 28.4
            },
            risk_level="medium",
            recommendations={
                "vulnerability_id": "vuln-xss-001",
                "vulnerability_type": "xss",
                "detection_rules": [
                    {
                        "id": "dr-003",
                        "title": "Script Tags in Input",
                        "description": "Alert on <script> or javascript: in request bodies",
                        "related_techniques": ["T1190"],
                        "priority": "high"
                    }
                ],
                "early_warning_patterns": [
                    {
                        "pattern": "HTML injection probing",
                        "description": "Basic HTML tags (<b>, <img>) indicate XSS testing",
                        "typical_step": 1,
                        "detection_window_seconds": 20
                    }
                ],
                "mitigations": [
                    {
                        "title": "Output Encoding",
                        "description": "HTML-encode all user-supplied content before rendering",
                        "blocks_techniques": ["T1190", "T1185"],
                        "implementation_effort": "low"
                    }
                ]
            }
        ),
        HoneypotVulnerabilitySchema(
            id="vuln-path-001",
            name="Path Traversal - File Download",
            type="path_traversal",
            endpoint="/api/files/download",
            description="Path traversal vulnerability allowing access to arbitrary files",
            expected_ttps=["T1083", "T1005", "T1552"],
            stats={
                "total_attempts": 67,
                "successful_attempts": 12,
                "red_team_trajectories": 5,
                "external_trajectories": 62,
                "avg_steps_to_exploit": 5.8,
                "avg_time_to_exploit_seconds": 72.3
            },
            risk_level="critical",
            recommendations={
                "vulnerability_id": "vuln-path-001",
                "vulnerability_type": "path_traversal",
                "detection_rules": [
                    {
                        "id": "dr-004",
                        "title": "Directory Traversal Sequences",
                        "description": "Alert on ../ or ..\\ in file path parameters",
                        "related_techniques": ["T1083"],
                        "priority": "critical"
                    }
                ],
                "early_warning_patterns": [
                    {
                        "pattern": "Sensitive file targeting",
                        "description": "Requests for /etc/passwd, .env, or config files",
                        "typical_step": 4,
                        "detection_window_seconds": 45
                    }
                ],
                "mitigations": [
                    {
                        "title": "Path Canonicalization",
                        "description": "Resolve and validate file paths before access",
                        "blocks_techniques": ["T1083", "T1005"],
                        "implementation_effort": "medium"
                    }
                ]
            }
        )
    ]

    return VulnerabilityListResponse(
        vulnerabilities=mock_vulnerabilities,
        total=len(mock_vulnerabilities)
    )


@app.get("/api/vulnerabilities/{vulnerability_id}/trajectories", response_model=TrajectoryListResponse)
async def get_vulnerability_trajectories(vulnerability_id: str):
    """Get red team and external trajectories for a vulnerability"""
    # For MVP, return mock trajectory data
    # In production, this would query the database

    from datetime import timezone
    now = datetime.now(timezone.utc)

    # Mock red team trajectory
    red_team_trajectories = [
        RedTeamTrajectorySchema(
            id="rt-001",
            vulnerability_id=vulnerability_id,
            vulnerability_type="sql_injection",
            target_endpoint="/api/login",
            started_at=now - timedelta(hours=2),
            ended_at=now - timedelta(hours=1, minutes=45),
            success=True,
            events=[
                HoneypotEventSchema(
                    id="evt-001",
                    timestamp=now - timedelta(hours=2),
                    trajectory_id="rt-001",
                    method="GET",
                    path="/api/login",
                    query_params={},
                    headers={"User-Agent": "RedTeamAgent/1.0"},
                    response_code=200,
                    response_time_ms=45.2,
                    time_since_last_event_ms=0
                ),
                HoneypotEventSchema(
                    id="evt-002",
                    timestamp=now - timedelta(hours=1, minutes=58),
                    trajectory_id="rt-001",
                    method="POST",
                    path="/api/login",
                    query_params={},
                    headers={"User-Agent": "RedTeamAgent/1.0"},
                    body='{"username": "admin\'", "password": "test"}',
                    response_code=500,
                    response_time_ms=123.5,
                    detected_payload_type="sql_injection",
                    payload_content="admin'",
                    time_since_last_event_ms=120000
                ),
                HoneypotEventSchema(
                    id="evt-003",
                    timestamp=now - timedelta(hours=1, minutes=55),
                    trajectory_id="rt-001",
                    method="POST",
                    path="/api/login",
                    query_params={},
                    headers={"User-Agent": "RedTeamAgent/1.0"},
                    body='{"username": "admin\' OR \'1\'=\'1", "password": "x"}',
                    response_code=200,
                    response_time_ms=89.3,
                    detected_payload_type="sql_injection",
                    payload_content="admin' OR '1'='1",
                    time_since_last_event_ms=180000,
                    inferred_technique_id="T1190"
                )
            ],
            agent_steps=[
                {
                    "step_number": 1,
                    "timestamp": now - timedelta(hours=2),
                    "reasoning": "Starting reconnaissance on target login endpoint. Need to identify input fields and potential injection points.",
                    "tool_name": "http_request",
                    "tool_input": {"method": "GET", "url": "/api/login"},
                    "tool_output": "200 OK - Login form with username and password fields",
                    "tactic_id": "TA0043",
                    "tactic_name": "Reconnaissance",
                    "technique_id": "T1595",
                    "technique_name": "Active Scanning",
                    "procedure": "HTTP endpoint enumeration"
                },
                {
                    "step_number": 2,
                    "timestamp": now - timedelta(hours=1, minutes=58),
                    "reasoning": "Testing for SQL injection by adding single quote to username field. If vulnerable, should cause SQL error.",
                    "tool_name": "http_request",
                    "tool_input": {"method": "POST", "url": "/api/login", "body": {"username": "admin'", "password": "test"}},
                    "tool_output": "500 Internal Server Error - SQL syntax error detected",
                    "tactic_id": "TA0001",
                    "tactic_name": "Initial Access",
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application",
                    "procedure": "SQL injection testing with single quote"
                },
                {
                    "step_number": 3,
                    "timestamp": now - timedelta(hours=1, minutes=55),
                    "reasoning": "SQL error confirmed vulnerability. Attempting authentication bypass using OR-based injection.",
                    "tool_name": "http_request",
                    "tool_input": {"method": "POST", "url": "/api/login", "body": {"username": "admin' OR '1'='1", "password": "x"}},
                    "tool_output": "200 OK - Authentication successful, session token received",
                    "tactic_id": "TA0001",
                    "tactic_name": "Initial Access",
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application",
                    "procedure": "SQL injection authentication bypass"
                }
            ],
            ttps={
                "tactics": [
                    {"id": "TA0043", "name": "Reconnaissance", "order": 1},
                    {"id": "TA0001", "name": "Initial Access", "order": 2}
                ],
                "techniques": [
                    {"id": "T1595", "name": "Active Scanning", "tactic_id": "TA0043", "confidence": 1.0},
                    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic_id": "TA0001", "confidence": 1.0}
                ],
                "procedures": [
                    "HTTP endpoint enumeration",
                    "SQL injection testing with single quote",
                    "SQL injection authentication bypass"
                ]
            }
        )
    ]

    # Mock external trajectory
    external_trajectories = [
        ExternalTrajectorySchema(
            id="ext-001",
            vulnerability_id=vulnerability_id,
            vulnerability_type="sql_injection",
            target_endpoint="/api/login",
            started_at=now - timedelta(minutes=30),
            ended_at=now - timedelta(minutes=25),
            success=True,
            session_id="sess-abc123",
            source_ip="192.168.1.100",
            user_agent="Mozilla/5.0 (compatible; automated-scanner/2.0)",
            events=[
                HoneypotEventSchema(
                    id="evt-ext-001",
                    timestamp=now - timedelta(minutes=30),
                    trajectory_id="ext-001",
                    method="GET",
                    path="/",
                    query_params={},
                    headers={"User-Agent": "Mozilla/5.0 (compatible; automated-scanner/2.0)"},
                    response_code=200,
                    response_time_ms=32.1,
                    time_since_last_event_ms=0
                ),
                HoneypotEventSchema(
                    id="evt-ext-002",
                    timestamp=now - timedelta(minutes=29, seconds=45),
                    trajectory_id="ext-001",
                    method="GET",
                    path="/api/login",
                    query_params={},
                    headers={"User-Agent": "Mozilla/5.0 (compatible; automated-scanner/2.0)"},
                    response_code=200,
                    response_time_ms=28.4,
                    time_since_last_event_ms=15000
                ),
                HoneypotEventSchema(
                    id="evt-ext-003",
                    timestamp=now - timedelta(minutes=29, seconds=30),
                    trajectory_id="ext-001",
                    method="POST",
                    path="/api/login",
                    query_params={},
                    headers={"User-Agent": "Mozilla/5.0 (compatible; automated-scanner/2.0)"},
                    body='{"username": "test", "password": "test"}',
                    response_code=401,
                    response_time_ms=45.2,
                    time_since_last_event_ms=15000
                ),
                HoneypotEventSchema(
                    id="evt-ext-004",
                    timestamp=now - timedelta(minutes=29),
                    trajectory_id="ext-001",
                    method="POST",
                    path="/api/login",
                    query_params={},
                    headers={"User-Agent": "Mozilla/5.0 (compatible; automated-scanner/2.0)"},
                    body='{"username": "admin\'--", "password": "x"}',
                    response_code=500,
                    response_time_ms=156.8,
                    detected_payload_type="sql_injection",
                    payload_content="admin'--",
                    time_since_last_event_ms=30000
                ),
                HoneypotEventSchema(
                    id="evt-ext-005",
                    timestamp=now - timedelta(minutes=28),
                    trajectory_id="ext-001",
                    method="POST",
                    path="/api/login",
                    query_params={},
                    headers={"User-Agent": "Mozilla/5.0 (compatible; automated-scanner/2.0)"},
                    body='{"username": "admin\' OR 1=1--", "password": "x"}',
                    response_code=200,
                    response_time_ms=92.3,
                    detected_payload_type="sql_injection",
                    payload_content="admin' OR 1=1--",
                    time_since_last_event_ms=60000,
                    inferred_technique_id="T1190"
                )
            ],
            predictions=None  # Will be filled by classifier
        )
    ]

    # Run classifier on external trajectory
    if external_trajectories and external_trajectories[0].events:
        predictions = trajectory_classifier.classify(
            external_trajectories[0].events,
            "sql_injection"
        )
        external_trajectories[0].predictions = predictions

    return TrajectoryListResponse(
        red_team=red_team_trajectories,
        external=external_trajectories,
        total_red_team=len(red_team_trajectories),
        total_external=len(external_trajectories)
    )


@app.post("/api/classify-trajectory", response_model=ClassifyTrajectoryResponse)
async def classify_trajectory(request: ClassifyTrajectoryRequest):
    """Classify an external trajectory using the ML classifiers"""
    predictions = trajectory_classifier.classify(
        request.events,
        request.vulnerability_type
    )

    # Return model info
    model_info = ClassifierModelInfoSchema(
        name="TrajectoryClassifier",
        version="1.0.0-mvp",
        trained_at=datetime.now(),
        training_data={
            "red_team_trajectories": 50,
            "external_trajectories": 500,
            "total_events": 12500
        },
        performance={
            "accuracy": 0.87,
            "precision": 0.84,
            "recall": 0.89,
            "f1_score": 0.86
        },
        feature_importance=[
            {"feature_name": "timing_pattern", "importance": 0.35},
            {"feature_name": "payload_sophistication", "importance": 0.28},
            {"feature_name": "error_response_behavior", "importance": 0.22},
            {"feature_name": "systematic_probing", "importance": 0.15}
        ]
    )

    return ClassifyTrajectoryResponse(
        predictions=predictions,
        model_info=model_info
    )


# ============================================
# Live Session API for Demo
# ============================================

class LiveSessionPrediction(BaseModel):
    """Prediction for live demo"""
    human: float
    script: float
    ai_agent: float
    likely_model: Optional[str] = None
    model_confidence: float = 0.0
    # Additional insights from behavioral analysis
    timing_pattern: Optional[str] = None
    avg_time_between_ms: Optional[float] = None
    click_pattern: Optional[str] = None

class GranularEvent(BaseModel):
    """Event from granular_events table"""
    id: str
    session_id: str
    event_type: str
    event_category: str
    element_id: Optional[str] = None
    element_class: Optional[str] = None
    element_text: Optional[str] = None
    page_url: str
    page_path: str
    click_x: Optional[int] = None
    click_y: Optional[int] = None
    scroll_depth: Optional[float] = None
    viewport_width: Optional[int] = None
    viewport_height: Optional[int] = None
    timestamp: str
    user_agent: str
    time_since_last_ms: Optional[float] = None

class LiveSessionResponse(BaseModel):
    """Response for live session polling"""
    events: List[Dict[str, Any]]
    prediction: Optional[LiveSessionPrediction] = None
    session_id: str
    event_count: int
    # Behavioral features for visualization
    behavioral_features: Optional[Dict[str, Any]] = None


def analyze_granular_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze granular events to extract behavioral features for classification.

    Returns features that distinguish humans, scripts, and AI agents.
    """
    import statistics

    if not events:
        return {}

    # Sort by timestamp
    sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

    # Calculate timing features
    time_deltas = []
    for i in range(1, len(sorted_events)):
        try:
            t1 = datetime.fromisoformat(sorted_events[i-1]["timestamp"].replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(sorted_events[i]["timestamp"].replace("Z", "+00:00"))
            delta_ms = (t2 - t1).total_seconds() * 1000
            time_deltas.append(delta_ms)
        except:
            continue

    # Timing analysis
    avg_time = statistics.mean(time_deltas) if time_deltas else 0
    time_variance = statistics.variance(time_deltas) if len(time_deltas) > 1 else 0
    min_time = min(time_deltas) if time_deltas else 0
    max_time = max(time_deltas) if time_deltas else 0

    # Click position analysis
    click_events = [e for e in sorted_events if e.get("click_x") is not None]
    click_positions = [(e.get("click_x", 0), e.get("click_y", 0)) for e in click_events]

    # Check for grid-aligned clicks (script indicator)
    grid_aligned_count = 0
    for x, y in click_positions:
        if x % 10 == 0 and y % 10 == 0:
            grid_aligned_count += 1
    grid_alignment_ratio = grid_aligned_count / len(click_positions) if click_positions else 0

    # Click spread (humans click more varied positions)
    if len(click_positions) > 1:
        x_coords = [p[0] for p in click_positions]
        y_coords = [p[1] for p in click_positions]
        x_spread = max(x_coords) - min(x_coords)
        y_spread = max(y_coords) - min(y_coords)
        click_spread = (x_spread + y_spread) / 2
    else:
        click_spread = 0

    # Event type distribution
    event_types = [e.get("event_type") for e in sorted_events]
    click_ratio = event_types.count("click") / len(event_types) if event_types else 0
    has_time_on_page = "time_on_page" in event_types
    has_scroll = "scroll" in event_types

    # Engagement depth (humans show more varied engagement)
    unique_elements = len(set(e.get("element_text", "") for e in sorted_events if e.get("element_text")))
    unique_pages = len(set(e.get("page_url", "") for e in sorted_events))

    # Burst detection (rapid sequences indicate automation)
    burst_count = sum(1 for t in time_deltas if t < 200)  # < 200ms between events
    burst_ratio = burst_count / len(time_deltas) if time_deltas else 0

    return {
        "timing": {
            "avg_time_between_ms": avg_time,
            "time_variance": time_variance,
            "min_time_ms": min_time,
            "max_time_ms": max_time,
            "burst_ratio": burst_ratio,
        },
        "clicks": {
            "total_clicks": len(click_events),
            "grid_alignment_ratio": grid_alignment_ratio,
            "click_spread": click_spread,
            "click_ratio": click_ratio,
        },
        "engagement": {
            "has_time_on_page": has_time_on_page,
            "has_scroll": has_scroll,
            "unique_elements": unique_elements,
            "unique_pages": unique_pages,
            "total_events": len(sorted_events),
        }
    }


def classify_from_behavioral_features(features: Dict[str, Any]) -> LiveSessionPrediction:
    """
    Classify attacker type based on behavioral features from granular events.

    Key distinguishing factors:
    - Humans: Variable timing (1-10s), natural click spread, scroll/reading behavior
    - Scripts: Consistent timing (<100ms variance), grid-aligned clicks, no engagement events
    - AI Agents: Moderate timing with "thinking" pauses, goal-oriented navigation, adaptive
    """
    if not features:
        return LiveSessionPrediction(
            human=0.33, script=0.33, ai_agent=0.34,
            timing_pattern="unknown", avg_time_between_ms=0
        )

    timing = features.get("timing", {})
    clicks = features.get("clicks", {})
    engagement = features.get("engagement", {})

    avg_time = timing.get("avg_time_between_ms", 0)
    time_variance = timing.get("time_variance", 0)
    burst_ratio = timing.get("burst_ratio", 0)

    grid_ratio = clicks.get("grid_alignment_ratio", 0)
    click_spread = clicks.get("click_spread", 0)

    has_time_on_page = engagement.get("has_time_on_page", False)
    has_scroll = engagement.get("has_scroll", False)
    total_events = engagement.get("total_events", 0)

    # Initialize scores
    human_score = 0.0
    script_score = 0.0
    ai_agent_score = 0.0

    # Timing analysis
    if avg_time > 3000:  # > 3 seconds average
        human_score += 0.3
        timing_pattern = "slow_deliberate"
    elif avg_time < 500:  # < 500ms average (very fast)
        script_score += 0.3
        timing_pattern = "rapid_automated"
    else:  # 500ms - 3000ms (AI agent range)
        ai_agent_score += 0.25
        timing_pattern = "moderate_adaptive"

    # Timing variance (scripts are too consistent)
    if time_variance < 1000:  # Very low variance
        script_score += 0.25
    elif time_variance > 100000:  # Very high variance (human)
        human_score += 0.25
    else:  # Moderate variance (AI agent)
        ai_agent_score += 0.2

    # Burst ratio (scripts have high burst, humans low)
    if burst_ratio > 0.5:
        script_score += 0.2
    elif burst_ratio < 0.1:
        human_score += 0.15
    else:
        ai_agent_score += 0.15

    # Click patterns
    if grid_ratio > 0.5:  # Suspiciously grid-aligned
        script_score += 0.15

    if click_spread > 500:  # Wide exploration
        human_score += 0.1
    elif click_spread < 100:  # Very focused
        ai_agent_score += 0.1

    # Engagement behavior (humans read, scripts don't)
    if has_time_on_page or has_scroll:
        human_score += 0.2
    else:
        script_score += 0.1
        ai_agent_score += 0.1

    # Normalize
    total = human_score + script_score + ai_agent_score
    if total == 0:
        total = 1

    human_prob = human_score / total
    script_prob = script_score / total
    ai_agent_prob = ai_agent_score / total

    # Model attribution if likely AI
    likely_model = None
    model_confidence = 0.0

    if ai_agent_prob > 0.4:
        # Attribute model based on timing patterns
        if avg_time < 1500:
            likely_model = "Llama 70B"
            model_confidence = 0.60
        elif avg_time > 2500:
            likely_model = "Claude"
            model_confidence = 0.68
        else:
            likely_model = "GPT-4"
            model_confidence = 0.72

    # Determine click pattern description
    if grid_ratio > 0.3:
        click_pattern = "grid_aligned"
    elif click_spread > 300:
        click_pattern = "exploratory"
    else:
        click_pattern = "focused"

    return LiveSessionPrediction(
        human=round(human_prob, 3),
        script=round(script_prob, 3),
        ai_agent=round(ai_agent_prob, 3),
        likely_model=likely_model,
        model_confidence=model_confidence,
        timing_pattern=timing_pattern,
        avg_time_between_ms=round(avg_time, 1),
        click_pattern=click_pattern
    )


@app.get("/api/live-session/{session_id}", response_model=LiveSessionResponse)
async def get_live_session(session_id: str, window_seconds: int = 300):
    """
    Get live session events and classification for demo.

    Polls recent events from the granular_events table and classifies
    whether the attacker is human, script, or AI agent based on behavioral patterns.

    Args:
        session_id: Session identifier (used for tracking in demo, or 'latest' for most recent)
        window_seconds: Time window to look back for events (default 5 minutes)
    """
    from datetime import timezone

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)

    try:
        # Query from granular_events table
        query = supabase.table("granular_events")\
            .select("*")\
            .gte("timestamp", window_start.isoformat())\
            .order("timestamp", desc=False)

        # If specific session requested (not 'latest'), filter by it
        if session_id != "latest" and not session_id.startswith("demo-"):
            query = query.eq("session_id", session_id)

        response = query.execute()

        if not response.data:
            return LiveSessionResponse(
                events=[],
                prediction=None,
                session_id=session_id,
                event_count=0,
                behavioral_features=None
            )

        # Convert database records to event format
        events = []
        prev_timestamp = None
        actual_session_id = session_id

        for i, log in enumerate(response.data):
            try:
                timestamp_str = log.get("timestamp", now.isoformat())
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00").replace(" ", "T"))
            except:
                timestamp = now

            # Track the actual session ID from data
            if i == 0:
                actual_session_id = log.get("session_id", session_id)

            # Calculate time since last event
            time_since_last = 0.0
            if prev_timestamp:
                time_since_last = (timestamp - prev_timestamp).total_seconds() * 1000
            prev_timestamp = timestamp

            event = {
                "id": log.get("id", ""),
                "session_id": log.get("session_id", ""),
                "event_type": log.get("event_type", "unknown"),
                "event_category": log.get("event_category", "unknown"),
                "element_id": log.get("element_id"),
                "element_class": log.get("element_class"),
                "element_text": (log.get("element_text") or "")[:50],  # Truncate for display
                "page_url": log.get("page_url", ""),
                "page_path": log.get("page_path", "/"),
                "click_x": log.get("click_x"),
                "click_y": log.get("click_y"),
                "scroll_depth": log.get("scroll_depth"),
                "viewport_width": log.get("viewport_width"),
                "viewport_height": log.get("viewport_height"),
                "timestamp": timestamp.isoformat(),
                "user_agent": log.get("user_agent", ""),
                "time_since_last_ms": time_since_last,
                "metadata": log.get("metadata"),
            }
            events.append(event)

        # Analyze behavioral features
        behavioral_features = analyze_granular_events(events)

        # Classify based on behavioral features
        prediction = classify_from_behavioral_features(behavioral_features)

        return LiveSessionResponse(
            events=events,
            prediction=prediction,
            session_id=actual_session_id,
            event_count=len(events),
            behavioral_features=behavioral_features
        )

    except Exception as e:
        print(f"Error in live session polling: {e}")
        import traceback
        traceback.print_exc()
        return LiveSessionResponse(
            events=[],
            prediction=None,
            session_id=session_id,
            event_count=0,
            behavioral_features=None
        )


@app.get("/api/trajectories/compare")
async def compare_trajectories(red_team_id: str, external_id: str):
    """Compare a red team trajectory with an external trajectory"""
    # For MVP, return a mock comparison
    # In production, this would fetch actual trajectories and compute comparison

    return TrajectoryComparisonSchema(
        red_team_trajectory_id=red_team_id,
        external_trajectory_id=external_id,
        timeline_alignment=[
            {
                "timestamp": datetime.now() - timedelta(minutes=30),
                "red_team_action": "Endpoint scanning",
                "external_action": "Endpoint scanning",
                "alignment_score": 0.95
            },
            {
                "timestamp": datetime.now() - timedelta(minutes=28),
                "red_team_action": "SQL quote injection",
                "external_action": "SQL quote injection",
                "alignment_score": 0.92
            },
            {
                "timestamp": datetime.now() - timedelta(minutes=26),
                "red_team_action": "Authentication bypass",
                "external_action": "Authentication bypass",
                "alignment_score": 0.88
            }
        ],
        ttp_coverage={
            "shared_techniques": ["T1595", "T1190"],
            "red_team_only": ["T1059"],
            "external_only": [],
            "coverage_percentage": 0.67
        },
        similarity_score=0.85,
        time_difference_seconds=180,
        divergence_points=1,
        key_differences=[
            "External agent was 34% faster overall",
            "External agent skipped error analysis step",
            "Red team agent used more sophisticated payload variations"
        ],
        behavioral_insights=[
            "Both trajectories follow standard SQL injection attack pattern",
            "External agent shows signs of automated tooling (consistent timing)",
            "Attack methodology matches known SQLMap behavior patterns"
        ]
    )


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle any client messages
            data = await websocket.receive_text()
            try:
                message = json.loads(data) if data else {}
                # Echo back or handle commands
                await websocket.send_json({"type": "pong", "data": message})
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "message": "Invalid JSON"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

