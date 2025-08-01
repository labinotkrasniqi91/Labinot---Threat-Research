from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio
from contextlib import asynccontextmanager

from siem.core.database import get_db, init_db, init_elasticsearch, check_connections
from siem.core.config import get_settings
from siem.core.event_processor import EventProcessor
from siem.models.events import (
    SecurityEventCreate, SecurityEventResponse,
    SecurityAlertCreate, SecurityAlertResponse,
    DetectionRuleCreate, DetectionRuleResponse,
    ThreatIntelligenceCreate, ThreatIntelligenceResponse,
    SecurityEvent, SecurityAlert, DetectionRule, ThreatIntelligence
)
from siem.api import events, alerts, rules, dashboard, search

settings = get_settings()

# Global event processor instance
event_processor = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global event_processor
    
    # Startup
    print("🚀 Starting SIEM application...")
    
    # Initialize databases
    try:
        check_connections()
        init_db()
        init_elasticsearch()
        print("✓ Database connections established")
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")
        raise
    
    # Start event processor
    event_processor = EventProcessor()
    processor_task = asyncio.create_task(event_processor.start())
    
    print("✓ SIEM application started successfully")
    
    yield
    
    # Shutdown
    print("🛑 Shutting down SIEM application...")
    
    if event_processor:
        await event_processor.stop()
    
    if not processor_task.done():
        processor_task.cancel()
        try:
            await processor_task
        except asyncio.CancelledError:
            pass
    
    print("✓ SIEM application shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="SIEM - Security Information and Event Management",
    description="A comprehensive SIEM system for security monitoring and incident response",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for the dashboard
app.mount("/static", StaticFiles(directory="static"), name="static")


# Root endpoint
@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint serving the dashboard"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIEM Dashboard</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
            .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
            .nav { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
            .nav a { margin-right: 20px; color: #3498db; text-decoration: none; }
            .nav a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ SIEM Dashboard</h1>
            <p>Security Information and Event Management System</p>
        </div>
        
        <div class="nav">
            <a href="/api/v1/events">📊 Events API</a>
            <a href="/api/v1/alerts">🚨 Alerts API</a>
            <a href="/api/v1/rules">📋 Rules API</a>
            <a href="/docs">📚 API Documentation</a>
            <a href="/kibana" target="_blank">📈 Kibana Dashboard</a>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="event-count">-</div>
                <div>Total Events (24h)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="alert-count">-</div>
                <div>Active Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="rule-count">-</div>
                <div>Detection Rules</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="threat-count">-</div>
                <div>Threat Indicators</div>
            </div>
        </div>
        
        <div style="background: white; padding: 20px; border-radius: 8px;">
            <h2>System Status</h2>
            <p>✅ Event Processing: Active</p>
            <p>✅ Correlation Engine: Running</p>
            <p>✅ Threat Intelligence: Updated</p>
            <p>✅ Data Storage: Operational</p>
        </div>
        
        <script>
            // Simple dashboard stats loading
            async function loadStats() {
                try {
                    const response = await fetch('/api/v1/dashboard/stats');
                    const stats = await response.json();
                    
                    document.getElementById('event-count').textContent = stats.events_24h || 0;
                    document.getElementById('alert-count').textContent = stats.active_alerts || 0;
                    document.getElementById('rule-count').textContent = stats.detection_rules || 0;
                    document.getElementById('threat-count').textContent = stats.threat_indicators || 0;
                } catch (error) {
                    console.error('Error loading stats:', error);
                }
            }
            
            // Load stats on page load and refresh every 30 seconds
            loadStats();
            setInterval(loadStats, 30000);
        </script>
    </body>
    </html>
    """


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "services": {
            "event_processor": event_processor.processing if event_processor else False,
            "database": True,  # Would check actual database health
            "elasticsearch": True,  # Would check actual ES health
            "redis": True  # Would check actual Redis health
        }
    }


# API v1 routes
@app.post("/api/v1/events", response_model=SecurityEventResponse)
async def create_event(
    event: SecurityEventCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Create a new security event"""
    try:
        # Convert Pydantic model to dict for processing
        event_data = event.dict()
        
        # Process event in background
        if event_processor:
            background_tasks.add_task(event_processor.process_event, event_data)
        
        # Create database record
        db_event = SecurityEvent(**event_data)
        db.add(db_event)
        db.commit()
        db.refresh(db_event)
        
        return db_event
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/events/batch")
async def create_events_batch(
    events_data: Dict[str, List[Dict[str, Any]]],
    background_tasks: BackgroundTasks
):
    """Create multiple security events in batch"""
    try:
        events = events_data.get("events", [])
        
        if not events:
            raise HTTPException(status_code=400, detail="No events provided")
        
        # Process events in background
        if event_processor:
            background_tasks.add_task(event_processor.process_batch, events)
        
        return {
            "message": f"Batch of {len(events)} events queued for processing",
            "count": len(events),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/events", response_model=List[SecurityEventResponse])
async def get_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=1000),
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    source_system: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    """Get security events with filtering"""
    try:
        query = db.query(SecurityEvent)
        
        # Apply filters
        if severity:
            query = query.filter(SecurityEvent.severity == severity)
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        if source_system:
            query = query.filter(SecurityEvent.source_system == source_system)
        if start_time:
            query = query.filter(SecurityEvent.timestamp >= start_time)
        if end_time:
            query = query.filter(SecurityEvent.timestamp <= end_time)
        
        # Order by timestamp descending
        query = query.order_by(SecurityEvent.timestamp.desc())
        
        # Apply pagination
        events = query.offset(skip).limit(limit).all()
        
        return events
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/events/{event_id}", response_model=SecurityEventResponse)
async def get_event(event_id: int, db: Session = Depends(get_db)):
    """Get a specific security event"""
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.post("/api/v1/alerts", response_model=SecurityAlertResponse)
async def create_alert(alert: SecurityAlertCreate, db: Session = Depends(get_db)):
    """Create a new security alert"""
    try:
        db_alert = SecurityAlert(**alert.dict())
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)
        return db_alert
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/alerts", response_model=List[SecurityAlertResponse])
async def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=1000),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get security alerts with filtering"""
    try:
        query = db.query(SecurityAlert)
        
        if status:
            query = query.filter(SecurityAlert.status == status)
        if severity:
            query = query.filter(SecurityAlert.severity == severity)
        
        query = query.order_by(SecurityAlert.created_at.desc())
        alerts = query.offset(skip).limit(limit).all()
        
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/alerts/{alert_id}", response_model=SecurityAlertResponse)
async def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get a specific security alert"""
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.put("/api/v1/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: int,
    status_data: Dict[str, str],
    db: Session = Depends(get_db)
):
    """Update alert status"""
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    new_status = status_data.get("status")
    if new_status not in ["open", "investigating", "resolved", "false_positive", "suppressed"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    alert.status = new_status
    alert.updated_at = datetime.utcnow()
    
    if "assigned_to" in status_data:
        alert.assigned_to = status_data["assigned_to"]
    
    db.commit()
    return {"message": "Alert status updated", "status": new_status}


@app.post("/api/v1/rules", response_model=DetectionRuleResponse)
async def create_rule(rule: DetectionRuleCreate, db: Session = Depends(get_db)):
    """Create a new detection rule"""
    try:
        # Check if rule_id already exists
        existing_rule = db.query(DetectionRule).filter(DetectionRule.rule_id == rule.rule_id).first()
        if existing_rule:
            raise HTTPException(status_code=400, detail="Rule ID already exists")
        
        db_rule = DetectionRule(**rule.dict())
        db.add(db_rule)
        db.commit()
        db.refresh(db_rule)
        return db_rule
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rules", response_model=List[DetectionRuleResponse])
async def get_rules(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=1000),
    enabled: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Get detection rules"""
    try:
        query = db.query(DetectionRule)
        
        if enabled is not None:
            query = query.filter(DetectionRule.enabled == enabled)
        
        query = query.order_by(DetectionRule.created_at.desc())
        rules = query.offset(skip).limit(limit).all()
        
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rules/{rule_id}", response_model=DetectionRuleResponse)
async def get_rule(rule_id: str, db: Session = Depends(get_db)):
    """Get a specific detection rule"""
    rule = db.query(DetectionRule).filter(DetectionRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@app.put("/api/v1/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str, db: Session = Depends(get_db)):
    """Toggle rule enabled/disabled status"""
    rule = db.query(DetectionRule).filter(DetectionRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule.enabled = not rule.enabled
    rule.updated_at = datetime.utcnow()
    db.commit()
    
    return {"message": f"Rule {'enabled' if rule.enabled else 'disabled'}", "enabled": rule.enabled}


@app.post("/api/v1/threat-intelligence", response_model=ThreatIntelligenceResponse)
async def create_threat_intel(threat: ThreatIntelligenceCreate, db: Session = Depends(get_db)):
    """Create a new threat intelligence indicator"""
    try:
        db_threat = ThreatIntelligence(**threat.dict())
        db.add(db_threat)
        db.commit()
        db.refresh(db_threat)
        return db_threat
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/threat-intelligence", response_model=List[ThreatIntelligenceResponse])
async def get_threat_intel(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=1000),
    indicator_type: Optional[str] = None,
    is_active: Optional[bool] = True,
    db: Session = Depends(get_db)
):
    """Get threat intelligence indicators"""
    try:
        query = db.query(ThreatIntelligence)
        
        if indicator_type:
            query = query.filter(ThreatIntelligence.indicator_type == indicator_type)
        if is_active is not None:
            query = query.filter(ThreatIntelligence.is_active == is_active)
        
        query = query.order_by(ThreatIntelligence.created_at.desc())
        threats = query.offset(skip).limit(limit).all()
        
        return threats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/dashboard/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics"""
    try:
        # Calculate 24h time window
        now = datetime.utcnow()
        yesterday = now - timedelta(days=1)
        
        # Count events in last 24h
        events_24h = db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= yesterday
        ).count()
        
        # Count active alerts
        active_alerts = db.query(SecurityAlert).filter(
            SecurityAlert.status.in_(["open", "investigating"])
        ).count()
        
        # Count detection rules
        detection_rules = db.query(DetectionRule).filter(
            DetectionRule.enabled == True
        ).count()
        
        # Count threat indicators
        threat_indicators = db.query(ThreatIntelligence).filter(
            ThreatIntelligence.is_active == True
        ).count()
        
        return {
            "events_24h": events_24h,
            "active_alerts": active_alerts,
            "detection_rules": detection_rules,
            "threat_indicators": threat_indicators,
            "timestamp": now.isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/search")
async def search_events(
    query: str = Query(..., description="Search query"),
    index: str = Query("security-events", description="Elasticsearch index"),
    size: int = Query(100, le=1000, description="Number of results"),
    from_: int = Query(0, ge=0, alias="from", description="Offset for pagination")
):
    """Search events using Elasticsearch"""
    try:
        from siem.core.database import get_elasticsearch
        es_client = get_elasticsearch()
        
        # Build Elasticsearch query
        search_body = {
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": ["message", "raw_log", "user", "source_ip", "process"]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": size,
            "from": from_
        }
        
        # Execute search
        result = es_client.search(index=index, body=search_body)
        
        return {
            "total": result["hits"]["total"]["value"],
            "hits": result["hits"]["hits"],
            "took": result["took"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "siem.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )