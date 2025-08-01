from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, Float, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum

from siem.core.database import Base


class SeverityLevel(str, Enum):
    """Severity levels for events and alerts"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    """Types of security events"""
    LOGIN = "login"
    LOGOUT = "logout"
    FAILED_LOGIN = "failed_login"
    FILE_ACCESS = "file_access"
    NETWORK_CONNECTION = "network_connection"
    PROCESS_EXECUTION = "process_execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALWARE_DETECTION = "malware_detection"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    SYSTEM_ANOMALY = "system_anomaly"
    CONFIGURATION_CHANGE = "configuration_change"


class AlertStatus(str, Enum):
    """Status of security alerts"""
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


# SQLAlchemy Models
class SecurityEvent(Base):
    """Security Event database model"""
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    event_type = Column(String(50), index=True)
    severity = Column(String(20), index=True)
    source_ip = Column(String(45), index=True)  # IPv6 compatible
    destination_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10))
    user = Column(String(100), index=True)
    process = Column(String(255))
    file_path = Column(String(500))
    command = Column(Text)
    message = Column(Text)
    raw_log = Column(Text)
    parsed_fields = Column(JSON)
    source_system = Column(String(100), index=True)
    correlation_id = Column(String(100), index=True)
    tags = Column(JSON)
    
    # Geolocation data
    country = Column(String(100))
    city = Column(String(100))
    latitude = Column(Float)
    longitude = Column(Float)
    
    # Relationships
    alerts = relationship("SecurityAlert", back_populates="event")


class SecurityAlert(Base):
    """Security Alert database model"""
    __tablename__ = "security_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    rule_id = Column(String(100), index=True)
    rule_name = Column(String(200))
    severity = Column(String(20), index=True)
    status = Column(String(20), default=AlertStatus.OPEN, index=True)
    title = Column(String(500))
    description = Column(Text)
    event_count = Column(Integer, default=1)
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    assigned_to = Column(String(100))
    tags = Column(JSON)
    metadata = Column(JSON)
    
    # Foreign key to the triggering event
    event_id = Column(Integer, ForeignKey("security_events.id"))
    event = relationship("SecurityEvent", back_populates="alerts")


class DetectionRule(Base):
    """Detection Rule database model"""
    __tablename__ = "detection_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(100), unique=True, index=True)
    name = Column(String(200))
    description = Column(Text)
    severity = Column(String(20))
    enabled = Column(Boolean, default=True)
    query = Column(Text)  # Elasticsearch query or SQL query
    query_type = Column(String(20), default="elasticsearch")  # elasticsearch, sql, sigma
    conditions = Column(JSON)  # Rule conditions and thresholds
    actions = Column(JSON)  # Actions to take when rule triggers
    tags = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String(100))
    
    # Rule statistics
    trigger_count = Column(Integer, default=0)
    last_triggered = Column(DateTime(timezone=True))


class ThreatIntelligence(Base):
    """Threat Intelligence database model"""
    __tablename__ = "threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String(50), index=True)  # ip, domain, hash, etc.
    indicator_value = Column(String(500), index=True)
    threat_type = Column(String(100))  # malware, botnet, c2, etc.
    confidence = Column(Float)  # 0.0 to 1.0
    source = Column(String(100))
    description = Column(Text)
    tags = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)


# Pydantic Models for API
class SecurityEventCreate(BaseModel):
    """Security Event creation model"""
    timestamp: Optional[datetime] = None
    event_type: EventType
    severity: SeverityLevel
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    file_path: Optional[str] = None
    command: Optional[str] = None
    message: str
    raw_log: Optional[str] = None
    parsed_fields: Optional[Dict[str, Any]] = None
    source_system: str
    tags: Optional[list] = None


class SecurityEventResponse(BaseModel):
    """Security Event response model"""
    id: int
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: Optional[str]
    user: Optional[str]
    process: Optional[str]
    file_path: Optional[str]
    command: Optional[str]
    message: str
    source_system: str
    correlation_id: Optional[str]
    tags: Optional[list]
    country: Optional[str]
    city: Optional[str]
    
    class Config:
        from_attributes = True


class SecurityAlertCreate(BaseModel):
    """Security Alert creation model"""
    rule_id: str
    rule_name: str
    severity: SeverityLevel
    title: str
    description: str
    event_id: Optional[int] = None
    tags: Optional[list] = None
    metadata: Optional[Dict[str, Any]] = None


class SecurityAlertResponse(BaseModel):
    """Security Alert response model"""
    id: int
    created_at: datetime
    updated_at: Optional[datetime]
    rule_id: str
    rule_name: str
    severity: str
    status: str
    title: str
    description: str
    event_count: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    assigned_to: Optional[str]
    tags: Optional[list]
    
    class Config:
        from_attributes = True


class DetectionRuleCreate(BaseModel):
    """Detection Rule creation model"""
    rule_id: str
    name: str
    description: str
    severity: SeverityLevel
    enabled: bool = True
    query: str
    query_type: str = "elasticsearch"
    conditions: Optional[Dict[str, Any]] = None
    actions: Optional[Dict[str, Any]] = None
    tags: Optional[list] = None


class DetectionRuleResponse(BaseModel):
    """Detection Rule response model"""
    id: int
    rule_id: str
    name: str
    description: str
    severity: str
    enabled: bool
    query: str
    query_type: str
    conditions: Optional[Dict[str, Any]]
    actions: Optional[Dict[str, Any]]
    tags: Optional[list]
    created_at: datetime
    updated_at: Optional[datetime]
    created_by: Optional[str]
    trigger_count: int
    last_triggered: Optional[datetime]
    
    class Config:
        from_attributes = True


class ThreatIntelligenceCreate(BaseModel):
    """Threat Intelligence creation model"""
    indicator_type: str
    indicator_value: str
    threat_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    description: Optional[str] = None
    tags: Optional[list] = None
    expires_at: Optional[datetime] = None


class ThreatIntelligenceResponse(BaseModel):
    """Threat Intelligence response model"""
    id: int
    indicator_type: str
    indicator_value: str
    threat_type: str
    confidence: float
    source: str
    description: Optional[str]
    tags: Optional[list]
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool
    
    class Config:
        from_attributes = True