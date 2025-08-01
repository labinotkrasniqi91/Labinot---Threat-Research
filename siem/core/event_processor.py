import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
from dataclasses import dataclass
from loguru import logger
import httpx
import re

from siem.models.events import SecurityEvent, SecurityEventCreate, SecurityAlert, SecurityAlertCreate
from siem.core.database import get_elasticsearch, get_redis
from siem.core.config import get_settings

settings = get_settings()


@dataclass
class CorrelationRule:
    """Correlation rule definition"""
    rule_id: str
    name: str
    description: str
    time_window: int  # seconds
    event_count_threshold: int
    conditions: Dict[str, Any]
    severity: str
    enabled: bool = True


class EventProcessor:
    """Event processing engine for correlation and enrichment"""
    
    def __init__(self):
        self.es_client = get_elasticsearch()
        self.redis_client = get_redis()
        self.correlation_rules = []
        self.event_buffer = deque(maxlen=10000)
        self.correlation_cache = defaultdict(list)
        self.processing = False
        
        # Load correlation rules
        self._load_correlation_rules()
    
    async def start(self):
        """Start the event processor"""
        logger.info("Starting event processor")
        self.processing = True
        
        # Start processing tasks
        tasks = [
            asyncio.create_task(self._correlation_loop()),
            asyncio.create_task(self._cleanup_loop())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            logger.error(f"Event processor error: {e}")
        finally:
            self.processing = False
    
    async def stop(self):
        """Stop the event processor"""
        logger.info("Stopping event processor")
        self.processing = False
    
    async def process_event(self, event_data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Process a single security event"""
        try:
            # Enrich event with additional data
            enriched_event = await self._enrich_event(event_data)
            
            # Store event in Elasticsearch
            await self._store_event(enriched_event)
            
            # Add to correlation buffer
            self.event_buffer.append(enriched_event)
            
            # Check for immediate correlations
            await self._check_correlations(enriched_event)
            
            return enriched_event
            
        except Exception as e:
            logger.error(f"Error processing event: {e}")
            return None
    
    async def process_batch(self, events: List[Dict[str, Any]]) -> List[SecurityEvent]:
        """Process a batch of security events"""
        processed_events = []
        
        for event_data in events:
            processed_event = await self.process_event(event_data)
            if processed_event:
                processed_events.append(processed_event)
        
        return processed_events
    
    async def _enrich_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with additional context"""
        enriched = event_data.copy()
        
        # Add correlation ID if not present
        if 'correlation_id' not in enriched:
            enriched['correlation_id'] = str(uuid.uuid4())
        
        # Geolocation enrichment for IP addresses
        if 'source_ip' in enriched and enriched['source_ip']:
            geo_data = await self._get_geolocation(enriched['source_ip'])
            if geo_data:
                enriched.update(geo_data)
        
        # Threat intelligence enrichment
        threat_data = await self._check_threat_intelligence(enriched)
        if threat_data:
            enriched['threat_indicators'] = threat_data
            # Escalate severity if threat detected
            if enriched.get('severity') != 'critical':
                enriched['severity'] = 'high'
        
        # User enrichment
        if 'user' in enriched and enriched['user']:
            user_data = await self._get_user_context(enriched['user'])
            if user_data:
                enriched['user_context'] = user_data
        
        # Process enrichment
        if 'process' in enriched and enriched['process']:
            process_data = await self._get_process_context(enriched['process'])
            if process_data:
                enriched['process_context'] = process_data
        
        return enriched
    
    async def _store_event(self, event_data: Dict[str, Any]):
        """Store event in Elasticsearch"""
        try:
            # Prepare document for Elasticsearch
            doc = event_data.copy()
            doc['@timestamp'] = datetime.utcnow().isoformat()
            
            # Index the document
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.es_client.index(
                    index="security-events",
                    body=doc
                )
            )
            
        except Exception as e:
            logger.error(f"Error storing event in Elasticsearch: {e}")
    
    async def _check_correlations(self, event_data: Dict[str, Any]):
        """Check event against correlation rules"""
        for rule in self.correlation_rules:
            if not rule.enabled:
                continue
            
            try:
                if await self._evaluate_correlation_rule(rule, event_data):
                    await self._trigger_alert(rule, event_data)
            except Exception as e:
                logger.error(f"Error evaluating correlation rule {rule.rule_id}: {e}")
    
    async def _evaluate_correlation_rule(self, rule: CorrelationRule, event_data: Dict[str, Any]) -> bool:
        """Evaluate if event matches correlation rule"""
        # Check basic conditions
        conditions = rule.conditions
        
        # Check event type condition
        if 'event_type' in conditions:
            if event_data.get('event_type') not in conditions['event_type']:
                return False
        
        # Check severity condition
        if 'severity' in conditions:
            if event_data.get('severity') not in conditions['severity']:
                return False
        
        # Check source IP condition
        if 'source_ip' in conditions:
            if event_data.get('source_ip') not in conditions['source_ip']:
                return False
        
        # Check user condition
        if 'user' in conditions:
            if event_data.get('user') not in conditions['user']:
                return False
        
        # Check time-based correlation
        if rule.event_count_threshold > 1:
            return await self._check_time_correlation(rule, event_data)
        
        return True
    
    async def _check_time_correlation(self, rule: CorrelationRule, event_data: Dict[str, Any]) -> bool:
        """Check time-based event correlation"""
        rule_key = f"correlation:{rule.rule_id}"
        current_time = datetime.utcnow()
        
        # Get correlation key based on rule conditions
        correlation_key = self._get_correlation_key(rule, event_data)
        full_key = f"{rule_key}:{correlation_key}"
        
        # Get existing events for this correlation
        existing_events = self.redis_client.lrange(full_key, 0, -1)
        
        # Filter events within time window
        valid_events = []
        cutoff_time = current_time - timedelta(seconds=rule.time_window)
        
        for event_json in existing_events:
            try:
                event = json.loads(event_json)
                event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                if event_time >= cutoff_time:
                    valid_events.append(event)
            except Exception:
                continue
        
        # Add current event
        valid_events.append(event_data)
        
        # Update Redis with valid events
        pipeline = self.redis_client.pipeline()
        pipeline.delete(full_key)
        for event in valid_events:
            pipeline.lpush(full_key, json.dumps(event, default=str))
        pipeline.expire(full_key, rule.time_window)
        pipeline.execute()
        
        # Check if threshold is met
        return len(valid_events) >= rule.event_count_threshold
    
    def _get_correlation_key(self, rule: CorrelationRule, event_data: Dict[str, Any]) -> str:
        """Generate correlation key based on rule conditions"""
        key_parts = []
        
        # Include relevant fields in correlation key
        for field in ['source_ip', 'user', 'destination_ip', 'process']:
            if field in rule.conditions and field in event_data:
                key_parts.append(f"{field}:{event_data[field]}")
        
        return "|".join(key_parts) if key_parts else "global"
    
    async def _trigger_alert(self, rule: CorrelationRule, event_data: Dict[str, Any]):
        """Trigger security alert"""
        try:
            alert_data = {
                'rule_id': rule.rule_id,
                'rule_name': rule.name,
                'severity': rule.severity,
                'title': f"Security Alert: {rule.name}",
                'description': rule.description,
                'metadata': {
                    'triggering_event': event_data,
                    'correlation_rule': {
                        'time_window': rule.time_window,
                        'threshold': rule.event_count_threshold
                    }
                }
            }
            
            # Store alert in Elasticsearch
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.es_client.index(
                    index="alerts",
                    body=alert_data
                )
            )
            
            # Send alert notification
            await self._send_alert_notification(alert_data)
            
            logger.warning(f"Security alert triggered: {rule.name}")
            
        except Exception as e:
            logger.error(f"Error triggering alert for rule {rule.rule_id}: {e}")
    
    async def _send_alert_notification(self, alert_data: Dict[str, Any]):
        """Send alert notification to external systems"""
        try:
            # Send to SIEM API
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://localhost:8000/api/v1/alerts",
                    json=alert_data,
                    timeout=10.0
                )
                
                if response.status_code != 200:
                    logger.error(f"Failed to send alert notification: {response.status_code}")
                    
        except Exception as e:
            logger.error(f"Error sending alert notification: {e}")
    
    async def _get_geolocation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get geolocation data for IP address"""
        try:
            # Check cache first
            cache_key = f"geo:{ip_address}"
            cached_data = self.redis_client.get(cache_key)
            
            if cached_data:
                return json.loads(cached_data)
            
            # Use a free geolocation service (in production, use a proper service)
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://ip-api.com/json/{ip_address}",
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        geo_data = {
                            'country': data.get('country'),
                            'city': data.get('city'),
                            'latitude': data.get('lat'),
                            'longitude': data.get('lon')
                        }
                        
                        # Cache for 24 hours
                        self.redis_client.setex(
                            cache_key,
                            86400,
                            json.dumps(geo_data)
                        )
                        
                        return geo_data
                        
        except Exception as e:
            logger.debug(f"Error getting geolocation for {ip_address}: {e}")
        
        return None
    
    async def _check_threat_intelligence(self, event_data: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """Check event against threat intelligence"""
        threats = []
        
        try:
            # Check IP addresses
            for ip_field in ['source_ip', 'destination_ip']:
                if ip_field in event_data and event_data[ip_field]:
                    threat = await self._check_ip_threat(event_data[ip_field])
                    if threat:
                        threats.append(threat)
            
            # Check domains
            domains = self._extract_domains_from_event(event_data)
            for domain in domains:
                threat = await self._check_domain_threat(domain)
                if threat:
                    threats.append(threat)
            
            # Check file hashes
            hashes = self._extract_hashes_from_event(event_data)
            for hash_value in hashes:
                threat = await self._check_hash_threat(hash_value)
                if threat:
                    threats.append(threat)
                    
        except Exception as e:
            logger.error(f"Error checking threat intelligence: {e}")
        
        return threats if threats else None
    
    async def _check_ip_threat(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP address against threat intelligence"""
        # Query threat intelligence database
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"indicator_type": "ip"}},
                        {"term": {"indicator_value": ip_address}},
                        {"term": {"is_active": True}}
                    ]
                }
            }
        }
        
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.es_client.search(
                    index="threat_intelligence",
                    body=query
                )
            )
            
            if result['hits']['total']['value'] > 0:
                hit = result['hits']['hits'][0]['_source']
                return {
                    'indicator_type': 'ip',
                    'indicator_value': ip_address,
                    'threat_type': hit.get('threat_type'),
                    'confidence': hit.get('confidence'),
                    'source': hit.get('source')
                }
                
        except Exception as e:
            logger.debug(f"Error checking IP threat {ip_address}: {e}")
        
        return None
    
    async def _check_domain_threat(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain against threat intelligence"""
        # Similar to IP check but for domains
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"indicator_type": "domain"}},
                        {"term": {"indicator_value": domain}},
                        {"term": {"is_active": True}}
                    ]
                }
            }
        }
        
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.es_client.search(
                    index="threat_intelligence",
                    body=query
                )
            )
            
            if result['hits']['total']['value'] > 0:
                hit = result['hits']['hits'][0]['_source']
                return {
                    'indicator_type': 'domain',
                    'indicator_value': domain,
                    'threat_type': hit.get('threat_type'),
                    'confidence': hit.get('confidence'),
                    'source': hit.get('source')
                }
                
        except Exception as e:
            logger.debug(f"Error checking domain threat {domain}: {e}")
        
        return None
    
    async def _check_hash_threat(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """Check file hash against threat intelligence"""
        # Similar to IP check but for file hashes
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"indicator_type": "hash"}},
                        {"term": {"indicator_value": hash_value}},
                        {"term": {"is_active": True}}
                    ]
                }
            }
        }
        
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.es_client.search(
                    index="threat_intelligence",
                    body=query
                )
            )
            
            if result['hits']['total']['value'] > 0:
                hit = result['hits']['hits'][0]['_source']
                return {
                    'indicator_type': 'hash',
                    'indicator_value': hash_value,
                    'threat_type': hit.get('threat_type'),
                    'confidence': hit.get('confidence'),
                    'source': hit.get('source')
                }
                
        except Exception as e:
            logger.debug(f"Error checking hash threat {hash_value}: {e}")
        
        return None
    
    def _extract_domains_from_event(self, event_data: Dict[str, Any]) -> List[str]:
        """Extract domain names from event data"""
        domains = []
        
        # Check common fields for domains
        text_fields = [
            event_data.get('message', ''),
            event_data.get('command', ''),
            event_data.get('raw_log', '')
        ]
        
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        for text in text_fields:
            if text:
                found_domains = re.findall(domain_pattern, str(text))
                domains.extend(found_domains)
        
        return list(set(domains))  # Remove duplicates
    
    def _extract_hashes_from_event(self, event_data: Dict[str, Any]) -> List[str]:
        """Extract file hashes from event data"""
        hashes = []
        
        # Check common fields for hashes
        text_fields = [
            event_data.get('message', ''),
            event_data.get('command', ''),
            event_data.get('raw_log', '')
        ]
        
        # Hash patterns (MD5, SHA1, SHA256)
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b'   # SHA256
        ]
        
        for text in text_fields:
            if text:
                for pattern in hash_patterns:
                    found_hashes = re.findall(pattern, str(text))
                    hashes.extend(found_hashes)
        
        return list(set(hashes))  # Remove duplicates
    
    async def _get_user_context(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user context information"""
        # In a real implementation, this would query user directory services
        # For now, return basic context
        return {
            'username': username,
            'last_seen': datetime.utcnow().isoformat(),
            'risk_score': 'low'  # Could be calculated based on user behavior
        }
    
    async def _get_process_context(self, process: str) -> Optional[Dict[str, Any]]:
        """Get process context information"""
        # In a real implementation, this would query process intelligence
        # For now, return basic context
        return {
            'process': process,
            'risk_score': 'low'  # Could be calculated based on process reputation
        }
    
    def _load_correlation_rules(self):
        """Load correlation rules from configuration"""
        # Default correlation rules
        default_rules = [
            CorrelationRule(
                rule_id="failed_login_attempts",
                name="Multiple Failed Login Attempts",
                description="Multiple failed login attempts from same IP",
                time_window=300,  # 5 minutes
                event_count_threshold=5,
                conditions={
                    "event_type": ["failed_login"],
                    "severity": ["medium", "high", "critical"]
                },
                severity="high"
            ),
            CorrelationRule(
                rule_id="privilege_escalation",
                name="Privilege Escalation Detected",
                description="Privilege escalation activity detected",
                time_window=60,  # 1 minute
                event_count_threshold=1,
                conditions={
                    "event_type": ["privilege_escalation"]
                },
                severity="critical"
            ),
            CorrelationRule(
                rule_id="malware_detection",
                name="Malware Activity Detected",
                description="Malware or suspicious activity detected",
                time_window=60,  # 1 minute
                event_count_threshold=1,
                conditions={
                    "event_type": ["malware_detection"]
                },
                severity="critical"
            )
        ]
        
        self.correlation_rules = default_rules
        logger.info(f"Loaded {len(self.correlation_rules)} correlation rules")
    
    async def _correlation_loop(self):
        """Main correlation processing loop"""
        while self.processing:
            try:
                # Process events in buffer for correlations
                if self.event_buffer:
                    # Process recent events
                    recent_events = list(self.event_buffer)[-100:]  # Last 100 events
                    
                    for event_data in recent_events:
                        await self._check_correlations(event_data)
                
                await asyncio.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Error in correlation loop: {e}")
                await asyncio.sleep(5)
    
    async def _cleanup_loop(self):
        """Cleanup old correlation data"""
        while self.processing:
            try:
                # Clean up old Redis keys
                # This would be more sophisticated in production
                await asyncio.sleep(3600)  # Run every hour
                
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(3600)