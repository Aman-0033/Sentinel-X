"""Deterministic Risk Engine for Sentinel-X (Section 42).

Keeps risk evaluation strictly decoupled from the raw ML classification model,
combining ML confidence, anomaly scores, threat intelligence reputation,
and historical telemetry into an auditable 0..100 risk score and mapped severity.
"""

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, Optional

# Severity mapping boundaries
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# Configurable baseline severity weights per attack category
DEFAULT_ATTACK_BASE_WEIGHTS: Dict[str, float] = {
    "BENIGN": 5.0,
    "NORMAL": 5.0,
    "PORT SCAN": 45.0,
    "BRUTE FORCE": 70.0,
    "DATA EXFILTRATION": 85.0,
    "MALWARE C2": 88.0,
    "DDOS": 92.0,
    "SQL INJECTION": 78.0,
}


@dataclass
class RiskEvaluationResult:
    """Auditable output from the deterministic risk engine."""

    risk_score: float
    severity: str
    breakdown: Dict[str, float]
    formula_version: str = "v1.0"


class RiskEngine:
    """Calculates deterministic risk scores based on weighted security telemetry."""

    def __init__(self, attack_weights: Optional[Dict[str, float]] = None):
        self.attack_weights = attack_weights or DEFAULT_ATTACK_BASE_WEIGHTS

    def evaluate_risk(
        self,
        attack_type: str,
        confidence: float,
        is_anomaly: bool = False,
        anomaly_score: Optional[float] = None,
        threat_intel_score: Optional[float] = None,
        historical_context: Optional[Dict[str, Any]] = None,
    ) -> RiskEvaluationResult:
        """Calculate deterministic risk score in range [0.0, 100.0] and map severity.

        Auditable formula:
            risk = clamp(base_attack_score * confidence + anomaly_boost + ti_boost + hist_boost, 0, 100)
        """
        norm_attack = str(attack_type or "BENIGN").strip().upper()
        base_weight = self.attack_weights.get(norm_attack, 50.0)

        # 1. Base component
        conf_clamped = max(0.0, min(1.0, float(confidence)))
        base_component = base_weight * conf_clamped

        # 2. Anomaly component
        anomaly_boost = 0.0
        if is_anomaly:
            anom_degree = float(anomaly_score) if anomaly_score is not None else 0.8
            anom_clamped = max(0.0, min(1.0, anom_degree))
            anomaly_boost = anom_clamped * 15.0

        # 3. Threat intelligence component (0..100 reputation score)
        ti_boost = 0.0
        if threat_intel_score is not None:
            ti_norm = max(0.0, min(100.0, float(threat_intel_score))) / 100.0
            ti_boost = ti_norm * 20.0

        # 4. Historical context component (prior offenses)
        hist_boost = 0.0
        if historical_context:
            prior_incidents = int(historical_context.get("prior_incidents_count", 0))
            hist_boost = min(15.0, prior_incidents * 5.0)

        # 5. Total aggregation
        if (
            norm_attack in ("BENIGN", "NORMAL")
            and not is_anomaly
            and (threat_intel_score is None or threat_intel_score < 20.0)
        ):
            # Benign traffic remains low risk unless accompanied by significant anomaly or bad TI
            raw_risk = min(20.0, base_component + ti_boost)
        else:
            raw_risk = base_component + anomaly_boost + ti_boost + hist_boost

        final_risk = round(max(0.0, min(100.0, raw_risk)), 2)

        # 6. Severity Mapping
        if final_risk < 40.0:
            severity = SEVERITY_LOW
        elif final_risk < 70.0:
            severity = SEVERITY_MEDIUM
        elif final_risk < 90.0:
            severity = SEVERITY_HIGH
        else:
            severity = SEVERITY_CRITICAL

        breakdown = {
            "base_component": round(base_component, 2),
            "anomaly_boost": round(anomaly_boost, 2),
            "threat_intel_boost": round(ti_boost, 2),
            "historical_boost": round(hist_boost, 2),
            "raw_total": round(raw_risk, 2),
            "final_risk_score": final_risk,
        }

        return RiskEvaluationResult(
            risk_score=final_risk,
            severity=severity,
            breakdown=breakdown,
        )


# Singleton instance for application services
_risk_engine = RiskEngine()


def calculate_risk_score(
    attack_type: str,
    confidence: float | Decimal,
    is_anomaly: bool = False,
    anomaly_score: Optional[float | Decimal] = None,
    threat_intel_score: Optional[float | Decimal] = None,
    historical_context: Optional[Dict[str, Any]] = None,
) -> RiskEvaluationResult:
    """Convenience functional interface for deterministic risk scoring."""
    return _risk_engine.evaluate_risk(
        attack_type=attack_type,
        confidence=float(confidence),
        is_anomaly=is_anomaly,
        anomaly_score=float(anomaly_score) if anomaly_score is not None else None,
        threat_intel_score=float(threat_intel_score) if threat_intel_score is not None else None,
        historical_context=historical_context,
    )
