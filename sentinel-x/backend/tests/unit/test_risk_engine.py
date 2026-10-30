"""Unit tests for the Deterministic Risk Engine (Section 42)."""

from app.services.risk_service import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    RiskEngine,
    calculate_risk_score,
)


def test_deterministic_scoring_consistency():
    """Verify same inputs always produce mathematically identical risk scores."""
    r1 = calculate_risk_score("Brute Force", confidence=0.90, is_anomaly=True, anomaly_score=0.85)
    r2 = calculate_risk_score("Brute Force", confidence=0.90, is_anomaly=True, anomaly_score=0.85)
    assert r1.risk_score == r2.risk_score
    assert r1.severity == r2.severity
    assert r1.breakdown == r2.breakdown


def test_benign_traffic_risk():
    """Benign network telemetry must remain bounded in the LOW severity bracket."""
    res = calculate_risk_score("Benign", confidence=0.98)
    assert res.risk_score < 40.0
    assert res.severity == SEVERITY_LOW


def test_ddos_high_severity_mapping():
    """DDoS attack with high confidence maps to CRITICAL severity."""
    res = calculate_risk_score("DDoS", confidence=0.95, is_anomaly=True, anomaly_score=0.90)
    assert res.risk_score >= 90.0
    assert res.severity == SEVERITY_CRITICAL


def test_anomaly_and_threat_intel_boosts():
    """Threat intel abuse score and anomaly flags increase final risk score deterministically."""
    baseline = calculate_risk_score("Port Scan", confidence=0.80)
    enriched = calculate_risk_score(
        "Port Scan",
        confidence=0.80,
        is_anomaly=True,
        anomaly_score=0.75,
        threat_intel_score=80.0,
    )
    assert enriched.risk_score > baseline.risk_score
    assert enriched.breakdown["threat_intel_boost"] == 16.0  # 0.8 * 20.0
    assert enriched.breakdown["anomaly_boost"] == 11.25  # 0.75 * 15.0


def test_historical_context_boost():
    """Prior incidents elevate risk for repeat offenders."""
    res = calculate_risk_score(
        "Brute Force",
        confidence=0.85,
        historical_context={"prior_incidents_count": 3},
    )
    assert res.breakdown["historical_boost"] == 15.0  # min(15.0, 3 * 5.0)


def test_score_clamping():
    """Risk scores never exceed 100.0 or fall below 0.0."""
    high = calculate_risk_score(
        "DDoS",
        confidence=1.0,
        is_anomaly=True,
        anomaly_score=1.0,
        threat_intel_score=100.0,
        historical_context={"prior_incidents_count": 10},
    )
    assert high.risk_score == 100.0

    low = calculate_risk_score("Benign", confidence=0.0)
    assert low.risk_score >= 0.0


def test_severity_boundaries():
    """Test exact threshold transitions: LOW < 40 <= MEDIUM < 70 <= HIGH < 90 <= CRITICAL."""
    engine = RiskEngine()
    # Mock base weights to trigger exact thresholds
    assert engine.evaluate_risk("Benign", 0.0).severity == SEVERITY_LOW

    # Boundary at 40
    res_39 = engine.evaluate_risk("Port Scan", 0.888)  # 45 * 0.888 = 39.96
    assert res_39.severity == SEVERITY_LOW

    res_40 = engine.evaluate_risk("Port Scan", 0.90)  # 45 * 0.9 = 40.5
    assert res_40.severity == SEVERITY_MEDIUM

    # Boundary at 70
    res_70 = engine.evaluate_risk("Brute Force", 1.0)  # 70 * 1.0 = 70.0
    assert res_70.severity == SEVERITY_HIGH

    # Boundary at 90
    res_90 = engine.evaluate_risk("DDoS", 0.98)  # 92 * 0.98 = 90.16
    assert res_90.severity == SEVERITY_CRITICAL
