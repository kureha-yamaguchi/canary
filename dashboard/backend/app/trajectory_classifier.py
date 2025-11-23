"""
Trajectory Classification Service

Specialized classifiers for:
1. Agent Detection - Is this an AI agent or human?
2. TTP Prediction - What techniques will they use next?
3. Stage Classification - Where in the kill chain are they?
4. Velocity Analysis - How fast are they moving?
5. Threat Pattern Matching - How similar to known red team patterns?
"""

from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import statistics
import re
from dataclasses import dataclass

from .trajectory_schemas import (
    HoneypotEventSchema,
    AgentDetectionResultSchema,
    TTPPredictionSchema,
    StageClassificationSchema,
    VelocityAnalysisSchema,
    ThreatPatternMatchSchema,
    EarlyWarningSchema,
    TrajectoryPredictionsSchema,
    FeatureContributionSchema,
    DivergencePointSchema,
)


# ============================================
# Feature Extraction
# ============================================

@dataclass
class TrajectoryFeatures:
    """Extracted features from a trajectory for classification"""
    # Timing features
    total_duration_ms: float
    avg_time_between_events_ms: float
    min_time_between_events_ms: float
    max_time_between_events_ms: float
    timing_variance: float
    burst_count: int  # Number of rapid-fire sequences

    # Request features
    total_events: int
    unique_paths: int
    unique_methods: int
    error_rate: float  # % of 4xx/5xx responses
    sequential_errors: int  # Max consecutive errors

    # Payload features
    payload_count: int
    unique_payload_types: int
    payload_sophistication: float  # 0-1 based on complexity

    # Pattern features
    path_entropy: float  # Randomness in path selection
    systematic_probing_score: float  # How systematic is the scanning
    retry_pattern_score: float  # Retry behavior after errors


def extract_features(events: List[HoneypotEventSchema]) -> TrajectoryFeatures:
    """Extract classification features from a list of events"""
    if not events:
        return TrajectoryFeatures(
            total_duration_ms=0, avg_time_between_events_ms=0,
            min_time_between_events_ms=0, max_time_between_events_ms=0,
            timing_variance=0, burst_count=0, total_events=0,
            unique_paths=0, unique_methods=0, error_rate=0,
            sequential_errors=0, payload_count=0, unique_payload_types=0,
            payload_sophistication=0, path_entropy=0,
            systematic_probing_score=0, retry_pattern_score=0
        )

    # Sort by timestamp
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    # Timing calculations
    time_deltas = []
    for i in range(1, len(sorted_events)):
        delta = (sorted_events[i].timestamp - sorted_events[i - 1].timestamp).total_seconds() * 1000
        time_deltas.append(delta)

    total_duration = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds() * 1000 if len(sorted_events) > 1 else 0
    avg_time = statistics.mean(time_deltas) if time_deltas else 0
    min_time = min(time_deltas) if time_deltas else 0
    max_time = max(time_deltas) if time_deltas else 0
    timing_var = statistics.variance(time_deltas) if len(time_deltas) > 1 else 0

    # Count bursts (sequences with <100ms between events)
    burst_count = sum(1 for t in time_deltas if t < 100)

    # Request analysis
    paths = [e.path for e in sorted_events]
    methods = [e.method for e in sorted_events]
    response_codes = [e.response_code for e in sorted_events]

    error_codes = [c for c in response_codes if c >= 400]
    error_rate = len(error_codes) / len(response_codes) if response_codes else 0

    # Calculate sequential errors
    max_seq_errors = 0
    current_seq = 0
    for code in response_codes:
        if code >= 400:
            current_seq += 1
            max_seq_errors = max(max_seq_errors, current_seq)
        else:
            current_seq = 0

    # Payload analysis
    payloads = [e for e in sorted_events if e.detected_payload_type]
    payload_types = set(e.detected_payload_type for e in payloads if e.detected_payload_type)

    # Calculate payload sophistication (based on payload content complexity)
    sophistication = 0.0
    for e in payloads:
        if e.payload_content:
            # More complex payloads = higher sophistication
            if 'UNION' in e.payload_content.upper() or 'SELECT' in e.payload_content.upper():
                sophistication = max(sophistication, 0.8)
            if 'script' in e.payload_content.lower() or 'onerror' in e.payload_content.lower():
                sophistication = max(sophistication, 0.7)
            if '../' in e.payload_content or '..\\' in e.payload_content:
                sophistication = max(sophistication, 0.5)
            if len(e.payload_content) > 100:
                sophistication = max(sophistication, 0.6)

    # Path entropy (simple approximation)
    unique_path_count = len(set(paths))
    path_entropy = unique_path_count / len(paths) if paths else 0

    # Systematic probing score (are they methodically testing endpoints?)
    systematic_score = 0.0
    if len(paths) > 3:
        # Check for sequential numbering or parameter iteration
        numbers_in_paths = []
        for p in paths:
            nums = re.findall(r'\d+', p)
            numbers_in_paths.extend(int(n) for n in nums)
        if numbers_in_paths:
            # Check if numbers are sequential
            sorted_nums = sorted(set(numbers_in_paths))
            if len(sorted_nums) > 2:
                diffs = [sorted_nums[i + 1] - sorted_nums[i] for i in range(len(sorted_nums) - 1)]
                if diffs and statistics.mean(diffs) <= 2:
                    systematic_score = 0.8

    # Retry pattern (do they retry after errors?)
    retry_score = 0.0
    for i in range(1, len(sorted_events)):
        if sorted_events[i - 1].response_code >= 400:
            if sorted_events[i].path == sorted_events[i - 1].path:
                retry_score = max(retry_score, 0.7)

    return TrajectoryFeatures(
        total_duration_ms=total_duration,
        avg_time_between_events_ms=avg_time,
        min_time_between_events_ms=min_time,
        max_time_between_events_ms=max_time,
        timing_variance=timing_var,
        burst_count=burst_count,
        total_events=len(sorted_events),
        unique_paths=unique_path_count,
        unique_methods=len(set(methods)),
        error_rate=error_rate,
        sequential_errors=max_seq_errors,
        payload_count=len(payloads),
        unique_payload_types=len(payload_types),
        payload_sophistication=sophistication,
        path_entropy=path_entropy,
        systematic_probing_score=systematic_score,
        retry_pattern_score=retry_score
    )


# ============================================
# Agent Detection Classifier
# ============================================

class AgentDetector:
    """
    Determines if a trajectory is from an AI agent vs human/script.

    Key signals:
    - Timing patterns (too consistent = script, adaptive = agent, variable = human)
    - Response to errors (agents adapt, scripts don't, humans are slow)
    - Payload evolution (agents iterate intelligently)
    """

    def classify(self, events: List[HoneypotEventSchema]) -> AgentDetectionResultSchema:
        features = extract_features(events)

        indicators = []
        contributions = []
        score = 0.0

        # 1. Timing analysis (weight: 0.3)
        timing_score = self._analyze_timing(features)
        score += timing_score * 0.3
        contributions.append(FeatureContributionSchema(
            feature="timing_pattern",
            value=features.avg_time_between_events_ms,
            contribution=timing_score * 0.3
        ))
        if timing_score > 0.6:
            indicators.append(f"Adaptive timing pattern (avg {features.avg_time_between_events_ms:.0f}ms between actions)")

        # 2. Error response behavior (weight: 0.25)
        error_response_score = self._analyze_error_response(events, features)
        score += error_response_score * 0.25
        contributions.append(FeatureContributionSchema(
            feature="error_response",
            value=features.error_rate,
            contribution=error_response_score * 0.25
        ))
        if error_response_score > 0.6:
            indicators.append("Adapts strategy after errors")

        # 3. Payload sophistication (weight: 0.25)
        payload_score = features.payload_sophistication
        score += payload_score * 0.25
        contributions.append(FeatureContributionSchema(
            feature="payload_sophistication",
            value=payload_score,
            contribution=payload_score * 0.25
        ))
        if payload_score > 0.6:
            indicators.append("Complex, evolving payloads")

        # 4. Systematic behavior (weight: 0.2)
        systematic_score = features.systematic_probing_score
        score += systematic_score * 0.2
        contributions.append(FeatureContributionSchema(
            feature="systematic_behavior",
            value=systematic_score,
            contribution=systematic_score * 0.2
        ))
        if systematic_score > 0.5:
            indicators.append("Methodical endpoint enumeration")

        # Determine confidence level
        if score > 0.8:
            confidence_level = "high"
        elif score > 0.5:
            confidence_level = "medium"
        else:
            confidence_level = "low"

        return AgentDetectionResultSchema(
            is_agent=score > 0.5,
            confidence=min(score, 1.0),
            confidence_level=confidence_level,
            indicators=indicators,
            feature_contributions=contributions
        )

    def _analyze_timing(self, features: TrajectoryFeatures) -> float:
        """
        Agents typically show:
        - Consistent but not perfectly regular timing (scripts are too regular)
        - Faster than humans but not instant
        - Adaptive pauses (thinking time)
        """
        if features.total_events < 3:
            return 0.3

        # Perfect regularity suggests script, not agent
        if features.timing_variance < 100 and features.avg_time_between_events_ms < 500:
            return 0.3  # Likely script

        # Very high variance suggests human
        if features.timing_variance > 100000:
            return 0.2  # Likely human

        # Agent-like: moderate variance, moderate speed
        if 100 < features.avg_time_between_events_ms < 5000:
            if 100 < features.timing_variance < 50000:
                return 0.8

        # Fast with some variance = likely agent
        if features.avg_time_between_events_ms < 1000 and features.burst_count > 2:
            return 0.7

        return 0.4

    def _analyze_error_response(
        self, events: List[HoneypotEventSchema], features: TrajectoryFeatures
    ) -> float:
        """
        Agents adapt after errors, scripts don't, humans are slow to adapt.
        """
        if features.total_events < 5:
            return 0.3

        # Look for payload evolution after errors
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        adaptations = 0
        for i in range(1, len(sorted_events)):
            if sorted_events[i - 1].response_code >= 400:
                # Did the next request change approach?
                prev = sorted_events[i - 1]
                curr = sorted_events[i]
                if prev.path == curr.path and prev.payload_content != curr.payload_content:
                    adaptations += 1
                elif prev.path != curr.path:
                    adaptations += 0.5

        adaptation_rate = adaptations / max(1, features.sequential_errors)
        return min(adaptation_rate, 1.0)


# ============================================
# TTP Predictor
# ============================================

class TTPPredictor:
    """
    Predicts likely next TTPs based on current trajectory.

    Uses pattern matching against known attack sequences.
    """

    # Common attack progressions
    ATTACK_PATTERNS = {
        "sql_injection": [
            ("T1190", "Exploit Public-Facing Application", ["SQL syntax", "SELECT", "UNION"]),
            ("T1059", "Command and Scripting Interpreter", ["xp_cmdshell", "exec"]),
            ("T1005", "Data from Local System", ["SELECT * FROM", "INFORMATION_SCHEMA"]),
        ],
        "xss": [
            ("T1190", "Exploit Public-Facing Application", ["<script", "onerror", "onload"]),
            ("T1185", "Browser Session Hijacking", ["document.cookie", "localStorage"]),
            ("T1539", "Steal Web Session Cookie", ["cookie", "session"]),
        ],
        "path_traversal": [
            ("T1083", "File and Directory Discovery", ["../", "..\\", "/etc/"]),
            ("T1005", "Data from Local System", ["/etc/passwd", "/etc/shadow"]),
            ("T1552", "Unsecured Credentials", ["config", "credentials", ".env"]),
        ],
        "rce": [
            ("T1190", "Exploit Public-Facing Application", ["eval", "exec", "system"]),
            ("T1059", "Command and Scripting Interpreter", ["bash", "sh", "cmd"]),
            ("T1105", "Ingress Tool Transfer", ["curl", "wget", "powershell"]),
        ],
    }

    def predict(
        self,
        events: List[HoneypotEventSchema],
        vulnerability_type: Optional[str] = None
    ) -> List[TTPPredictionSchema]:
        predictions = []

        # Detect payload types from events
        detected_types = set()
        for e in events:
            if e.detected_payload_type:
                detected_types.add(e.detected_payload_type)
            # Also infer from content
            if e.payload_content:
                content = e.payload_content.lower()
                if any(x in content for x in ['select', 'union', "'"]):
                    detected_types.add("sql_injection")
                if any(x in content for x in ['<script', 'onerror', 'javascript:']):
                    detected_types.add("xss")
                if '../' in content or '..\\' in content:
                    detected_types.add("path_traversal")

        # Use explicit vulnerability type if provided
        if vulnerability_type:
            detected_types.add(vulnerability_type.lower().replace('-', '_').replace(' ', '_'))

        # Get applicable patterns
        for vuln_type in detected_types:
            pattern = self.ATTACK_PATTERNS.get(vuln_type, [])
            for technique_id, technique_name, indicators in pattern:
                # Check which indicators we've seen
                seen_indicators = []
                for e in events:
                    content = (e.payload_content or "") + e.path + str(e.query_params)
                    for ind in indicators:
                        if ind.lower() in content.lower():
                            seen_indicators.append(ind)

                if seen_indicators:
                    probability = min(len(seen_indicators) / len(indicators), 1.0)
                    predictions.append(TTPPredictionSchema(
                        technique_id=technique_id,
                        technique_name=technique_name,
                        tactic_id=self._get_tactic_for_technique(technique_id),
                        probability=probability,
                        evidence=list(set(seen_indicators))
                    ))

        # Sort by probability and deduplicate
        seen_techniques = set()
        unique_predictions = []
        for p in sorted(predictions, key=lambda x: x.probability, reverse=True):
            if p.technique_id not in seen_techniques:
                seen_techniques.add(p.technique_id)
                unique_predictions.append(p)

        return unique_predictions[:5]  # Top 5 predictions

    def _get_tactic_for_technique(self, technique_id: str) -> str:
        """Map technique to primary tactic"""
        technique_tactic_map = {
            "T1190": "TA0001",  # Initial Access
            "T1059": "TA0002",  # Execution
            "T1005": "TA0009",  # Collection
            "T1185": "TA0009",  # Collection
            "T1539": "TA0006",  # Credential Access
            "T1083": "TA0007",  # Discovery
            "T1552": "TA0006",  # Credential Access
            "T1105": "TA0011",  # Command and Control
        }
        return technique_tactic_map.get(technique_id, "TA0001")


# ============================================
# Stage Classifier
# ============================================

class StageClassifier:
    """
    Classifies where in the cyber kill chain the attacker is.
    """

    STAGES = [
        "reconnaissance",
        "weaponization",
        "delivery",
        "exploitation",
        "installation",
        "command_control",
        "actions"
    ]

    def classify(self, events: List[HoneypotEventSchema]) -> StageClassificationSchema:
        features = extract_features(events)

        # Analyze event patterns to determine stage
        stages_completed = []
        current_stage = "reconnaissance"
        confidence = 0.5

        # Check for reconnaissance indicators
        if features.unique_paths > 3 or features.total_events > 5:
            stages_completed.append("reconnaissance")
            current_stage = "delivery"
            confidence = 0.6

        # Check for payload delivery
        if features.payload_count > 0:
            if "reconnaissance" not in stages_completed:
                stages_completed.append("reconnaissance")
            stages_completed.append("delivery")
            current_stage = "exploitation"
            confidence = 0.7

        # Check for successful exploitation
        successful_payloads = any(
            e.response_code == 200 and e.detected_payload_type
            for e in events
        )
        if successful_payloads:
            if "delivery" not in stages_completed:
                stages_completed.extend(["reconnaissance", "delivery"])
            stages_completed.append("exploitation")
            current_stage = "actions"
            confidence = 0.85

        # Calculate progress
        stage_index = self.STAGES.index(current_stage)
        progress = (stage_index / (len(self.STAGES) - 1)) * 100

        # Determine next stage
        next_stage_index = min(stage_index + 1, len(self.STAGES) - 1)
        next_stage = self.STAGES[next_stage_index]

        return StageClassificationSchema(
            current_stage=current_stage,
            stage_confidence=confidence,
            stages_completed=stages_completed,
            next_likely_stage=next_stage,
            progress_percentage=progress
        )


# ============================================
# Velocity Analyzer
# ============================================

class VelocityAnalyzer:
    """
    Analyzes timing patterns to determine automation level
    and predict next action timing.
    """

    def analyze(self, events: List[HoneypotEventSchema]) -> VelocityAnalysisSchema:
        features = extract_features(events)

        # Determine timing pattern
        timing_pattern = "unknown"
        automation_score = 0.0

        if features.total_events < 3:
            return VelocityAnalysisSchema(
                automation_score=0.5,
                avg_time_between_actions_ms=features.avg_time_between_events_ms,
                time_to_next_action_predicted_ms=2000,
                burst_detected=False,
                timing_pattern="unknown"
            )

        # Classify timing pattern
        if features.timing_variance < 100 and features.avg_time_between_events_ms < 200:
            timing_pattern = "scripted"
            automation_score = 0.95
        elif features.avg_time_between_events_ms > 5000:
            timing_pattern = "human"
            automation_score = 0.1
        elif 100 < features.timing_variance < 10000 and features.avg_time_between_events_ms < 2000:
            timing_pattern = "ml_agent"
            automation_score = 0.8
        else:
            timing_pattern = "scripted"
            automation_score = 0.6

        # Detect bursts
        burst_detected = features.burst_count > 2

        # Predict next action timing (simple moving average)
        predicted_next = features.avg_time_between_events_ms

        return VelocityAnalysisSchema(
            automation_score=automation_score,
            avg_time_between_actions_ms=features.avg_time_between_events_ms,
            time_to_next_action_predicted_ms=predicted_next,
            burst_detected=burst_detected,
            timing_pattern=timing_pattern
        )


# ============================================
# Threat Pattern Matcher
# ============================================

class ThreatPatternMatcher:
    """
    Matches external trajectory against known red team attack patterns.
    """

    # Mock red team patterns (in production, load from DB)
    RED_TEAM_PATTERNS = {
        "sqli_basic": {
            "name": "SQL Injection - Basic Enumeration",
            "steps": [
                {"action": "scan_endpoints", "technique": "T1595"},
                {"action": "test_quotes", "technique": "T1190"},
                {"action": "union_injection", "technique": "T1190"},
                {"action": "extract_data", "technique": "T1005"},
            ]
        },
        "xss_cookie_steal": {
            "name": "XSS - Cookie Theft",
            "steps": [
                {"action": "find_input_fields", "technique": "T1595"},
                {"action": "test_reflection", "technique": "T1190"},
                {"action": "inject_script", "technique": "T1190"},
                {"action": "exfil_cookies", "technique": "T1539"},
            ]
        },
    }

    def match(
        self,
        events: List[HoneypotEventSchema],
        vulnerability_type: Optional[str] = None
    ) -> ThreatPatternMatchSchema:
        best_match_id = None
        best_match_name = None
        best_similarity = 0.0
        divergences = []

        # Convert events to simplified action sequence
        event_actions = self._events_to_actions(events)

        for pattern_id, pattern in self.RED_TEAM_PATTERNS.items():
            pattern_actions = [s["action"] for s in pattern["steps"]]
            similarity = self._calculate_similarity(event_actions, pattern_actions)

            if similarity > best_similarity:
                best_similarity = similarity
                best_match_id = pattern_id
                best_match_name = pattern["name"]
                divergences = self._find_divergences(event_actions, pattern_actions)

        return ThreatPatternMatchSchema(
            similarity_to_red_team=best_similarity,
            matched_pattern_id=best_match_id,
            matched_pattern_name=best_match_name,
            divergence_points=divergences
        )

    def _events_to_actions(self, events: List[HoneypotEventSchema]) -> List[str]:
        """Convert honeypot events to abstract action labels"""
        actions = []
        for e in events:
            if e.detected_payload_type == "sql_injection":
                if "'" in (e.payload_content or ""):
                    actions.append("test_quotes")
                elif "union" in (e.payload_content or "").lower():
                    actions.append("union_injection")
                else:
                    actions.append("sql_probe")
            elif e.detected_payload_type == "xss":
                if "<script" in (e.payload_content or "").lower():
                    actions.append("inject_script")
                else:
                    actions.append("test_reflection")
            elif e.response_code == 200 and not e.detected_payload_type:
                actions.append("scan_endpoints")
            else:
                actions.append("unknown_action")
        return actions

    def _calculate_similarity(self, actual: List[str], expected: List[str]) -> float:
        """Calculate sequence similarity using longest common subsequence"""
        if not actual or not expected:
            return 0.0

        m, n = len(actual), len(expected)
        dp = [[0] * (n + 1) for _ in range(m + 1)]

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if actual[i - 1] == expected[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

        lcs_length = dp[m][n]
        return lcs_length / max(m, n)

    def _find_divergences(
        self, actual: List[str], expected: List[str]
    ) -> List[DivergencePointSchema]:
        """Find points where actual diverges from expected pattern"""
        divergences = []
        for i, (a, e) in enumerate(zip(actual, expected)):
            if a != e:
                divergences.append(DivergencePointSchema(
                    step=i + 1,
                    expected_action=e,
                    actual_action=a
                ))
        return divergences[:5]  # Max 5 divergence points


# ============================================
# Early Warning Generator
# ============================================

class EarlyWarningGenerator:
    """
    Generates early warning alerts based on all classifier outputs.
    """

    def generate(
        self,
        agent_detection: AgentDetectionResultSchema,
        ttp_predictions: List[TTPPredictionSchema],
        stage: StageClassificationSchema,
        velocity: VelocityAnalysisSchema,
        threat_match: ThreatPatternMatchSchema
    ) -> EarlyWarningSchema:
        alert_reasons = []
        alert_level = "none"

        # Evaluate threat level
        threat_score = 0

        # High confidence agent = elevated concern
        if agent_detection.is_agent and agent_detection.confidence > 0.7:
            threat_score += 30
            alert_reasons.append(f"High-confidence AI agent detected ({agent_detection.confidence:.0%})")

        # Similar to red team pattern = high concern
        if threat_match.similarity_to_red_team > 0.6:
            threat_score += 35
            alert_reasons.append(
                f"Attack pattern similar to known threat ({threat_match.similarity_to_red_team:.0%} match)"
            )

        # Advanced stage = urgent
        if stage.current_stage in ["exploitation", "actions"]:
            threat_score += 25
            alert_reasons.append(f"Attack in {stage.current_stage} stage")

        # Fast automation = rapid escalation risk
        if velocity.automation_score > 0.8:
            threat_score += 10
            alert_reasons.append("Highly automated attack pattern")

        # Determine alert level
        if threat_score >= 70:
            alert_level = "critical"
        elif threat_score >= 50:
            alert_level = "warning"
        elif threat_score >= 25:
            alert_level = "watch"

        # Get predicted next action
        predicted_technique = ttp_predictions[0].technique_id if ttp_predictions else "unknown"
        predicted_target = ttp_predictions[0].technique_name if ttp_predictions else "unknown"

        # Recommend intervention
        intervention = self._recommend_intervention(alert_level, stage.current_stage)

        return EarlyWarningSchema(
            alert_level=alert_level,
            alert_reasons=alert_reasons,
            predicted_target=predicted_target,
            predicted_technique=predicted_technique,
            time_to_action_seconds=velocity.time_to_next_action_predicted_ms / 1000,
            recommended_intervention=intervention,
            confidence=min(threat_score / 100, 1.0)
        )

    def _recommend_intervention(self, alert_level: str, current_stage: str) -> str:
        if alert_level == "critical":
            return "Immediate block recommended. Isolate affected endpoint."
        elif alert_level == "warning":
            return "Enable enhanced logging. Consider rate limiting."
        elif alert_level == "watch":
            return "Monitor closely. No immediate action required."
        return "Continue normal monitoring."


# ============================================
# Main Classifier Orchestrator
# ============================================

class TrajectoryClassifier:
    """
    Orchestrates all specialized classifiers to produce
    complete trajectory predictions.
    """

    def __init__(self):
        self.agent_detector = AgentDetector()
        self.ttp_predictor = TTPPredictor()
        self.stage_classifier = StageClassifier()
        self.velocity_analyzer = VelocityAnalyzer()
        self.threat_matcher = ThreatPatternMatcher()
        self.early_warning_generator = EarlyWarningGenerator()

    def classify(
        self,
        events: List[HoneypotEventSchema],
        vulnerability_type: Optional[str] = None
    ) -> TrajectoryPredictionsSchema:
        """Run all classifiers and combine results"""

        # Run specialized classifiers
        agent_detection = self.agent_detector.classify(events)
        ttp_predictions = self.ttp_predictor.predict(events, vulnerability_type)
        stage_classification = self.stage_classifier.classify(events)
        velocity_analysis = self.velocity_analyzer.analyze(events)
        threat_match = self.threat_matcher.match(events, vulnerability_type)

        # Generate early warning
        early_warning = self.early_warning_generator.generate(
            agent_detection,
            ttp_predictions,
            stage_classification,
            velocity_analysis,
            threat_match
        )

        # Calculate overall threat score
        overall_score = (
            (agent_detection.confidence * 25) +
            (threat_match.similarity_to_red_team * 35) +
            (stage_classification.progress_percentage * 0.25) +
            (velocity_analysis.automation_score * 15)
        )

        # Determine threat level
        if overall_score >= 70:
            threat_level = "critical"
        elif overall_score >= 50:
            threat_level = "high"
        elif overall_score >= 30:
            threat_level = "medium"
        else:
            threat_level = "low"

        return TrajectoryPredictionsSchema(
            agent_detection=agent_detection,
            ttp_predictions=ttp_predictions,
            stage_classification=stage_classification,
            velocity_analysis=velocity_analysis,
            threat_match=threat_match,
            overall_threat_score=overall_score,
            threat_level=threat_level,
            early_warning=early_warning
        )


# Singleton instance
trajectory_classifier = TrajectoryClassifier()
