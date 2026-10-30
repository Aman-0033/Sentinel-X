"""SOC Dashboard KPI and Visualization Schemas (Section 16)."""

from typing import Optional

from pydantic import BaseModel, ConfigDict


class DashboardSummaryData(BaseModel):
    """Overall security posture and metrics."""

    model_config = ConfigDict(from_attributes=True)

    active_threats: int
    critical_threats: int
    open_incidents: int
    traffic_volume: int
    security_score: int  # 0 to 100 health index


class TrendPoint(BaseModel):
    """Time-series threat observation point."""

    timestamp: str
    count: int
    severity: Optional[str] = None
    attack_type: Optional[str] = None


class AttackDistributionItem(BaseModel):
    """Categorized attack frequency."""

    attack_type: str
    count: int
    percentage: float


class TopSourceItem(BaseModel):
    """High-risk network telemetry origin."""

    source_ip: str
    attack_count: int
    max_severity: str
    max_risk_score: float
    country: Optional[str] = None
