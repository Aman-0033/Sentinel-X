"""Network Flow and Data Source Repository.

Data access layer for network telemetry and telemetry data sources.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.db.models.data_source import DataSource
from app.db.models.network_flow import NetworkFlow


class NetworkFlowRepository:
    """Repository handling database operations for network flows and data sources."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, flow_id: str) -> Optional[NetworkFlow]:
        """Fetch network flow by primary key ID."""
        return self.db.query(NetworkFlow).filter(NetworkFlow.id == flow_id).first()

    def create(self, **kwargs) -> NetworkFlow:
        """Create and persist a single network flow."""
        flow = NetworkFlow(**kwargs)
        self.db.add(flow)
        self.db.commit()
        self.db.refresh(flow)
        return flow

    def create_batch(self, flows_data: List[Dict[str, Any]]) -> List[NetworkFlow]:
        """Bulk insert a batch of validated network flows within a transaction."""
        flow_objects = [NetworkFlow(**data) for data in flows_data]
        self.db.add_all(flow_objects)
        self.db.commit()
        for flow in flow_objects:
            self.db.refresh(flow)
        return flow_objects

    def list_flows(
        self,
        skip: int = 0,
        limit: int = 50,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[NetworkFlow]:
        """List network flows with multi-criteria filtering and pagination."""
        query = self.db.query(NetworkFlow)
        if source_ip:
            query = query.filter(NetworkFlow.source_ip == source_ip)
        if destination_ip:
            query = query.filter(NetworkFlow.destination_ip == destination_ip)
        if start_time:
            query = query.filter(NetworkFlow.timestamp >= start_time)
        if end_time:
            query = query.filter(NetworkFlow.timestamp <= end_time)
        return query.order_by(NetworkFlow.timestamp.desc()).offset(skip).limit(limit).all()

    def count_flows(
        self,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """Count total network flows matching filters."""
        query = self.db.query(NetworkFlow)
        if source_ip:
            query = query.filter(NetworkFlow.source_ip == source_ip)
        if destination_ip:
            query = query.filter(NetworkFlow.destination_ip == destination_ip)
        if start_time:
            query = query.filter(NetworkFlow.timestamp >= start_time)
        if end_time:
            query = query.filter(NetworkFlow.timestamp <= end_time)
        return query.count()

    def create_data_source(self, **kwargs) -> DataSource:
        """Register a new telemetry data source."""
        data_source = DataSource(**kwargs)
        self.db.add(data_source)
        self.db.commit()
        self.db.refresh(data_source)
        return data_source

    def get_data_source_by_id(self, source_id: str) -> Optional[DataSource]:
        """Fetch telemetry data source by ID."""
        return self.db.query(DataSource).filter(DataSource.id == source_id).first()

    def list_data_sources(self) -> List[DataSource]:
        """List all telemetry data sources."""
        return self.db.query(DataSource).order_by(DataSource.created_at.desc()).all()
