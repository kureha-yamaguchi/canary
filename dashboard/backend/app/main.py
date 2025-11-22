"""FastAPI main application"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn
from typing import List, Dict, Any
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

