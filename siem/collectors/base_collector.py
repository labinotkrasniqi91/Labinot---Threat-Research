import asyncio
import json
import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, List, Optional, AsyncGenerator
from loguru import logger
import httpx

from siem.models.events import SecurityEventCreate, EventType, SeverityLevel


class BaseCollector(ABC):
    """Base class for all log collectors"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.running = False
        self.api_url = config.get("api_url", "http://localhost:8000")
        self.batch_size = config.get("batch_size", 100)
        self.flush_interval = config.get("flush_interval", 5)  # seconds
        self.event_buffer = []
        
    @abstractmethod
    async def collect_events(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Collect raw log events from the source"""
        pass
    
    @abstractmethod
    def parse_event(self, raw_event: str) -> Optional[SecurityEventCreate]:
        """Parse raw log event into structured SecurityEvent"""
        pass
    
    async def start(self):
        """Start the collector"""
        logger.info(f"Starting collector: {self.name}")
        self.running = True
        
        # Start collection and processing tasks
        tasks = [
            asyncio.create_task(self._collect_loop()),
            asyncio.create_task(self._flush_loop())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            logger.error(f"Collector {self.name} error: {e}")
        finally:
            self.running = False
    
    async def stop(self):
        """Stop the collector"""
        logger.info(f"Stopping collector: {self.name}")
        self.running = False
        
        # Flush remaining events
        if self.event_buffer:
            await self._flush_events()
    
    async def _collect_loop(self):
        """Main collection loop"""
        async for raw_event in self.collect_events():
            if not self.running:
                break
                
            try:
                parsed_event = self.parse_event(raw_event)
                if parsed_event:
                    self.event_buffer.append(parsed_event)
                    
                    # Flush if buffer is full
                    if len(self.event_buffer) >= self.batch_size:
                        await self._flush_events()
                        
            except Exception as e:
                logger.error(f"Error parsing event in {self.name}: {e}")
                logger.debug(f"Raw event: {raw_event}")
    
    async def _flush_loop(self):
        """Periodic flush loop"""
        while self.running:
            await asyncio.sleep(self.flush_interval)
            if self.event_buffer:
                await self._flush_events()
    
    async def _flush_events(self):
        """Flush events to SIEM API"""
        if not self.event_buffer:
            return
            
        events_to_send = self.event_buffer.copy()
        self.event_buffer.clear()
        
        try:
            async with httpx.AsyncClient() as client:
                # Convert Pydantic models to dict for JSON serialization
                events_data = [event.dict() for event in events_to_send]
                
                response = await client.post(
                    f"{self.api_url}/api/v1/events/batch",
                    json={"events": events_data},
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    logger.debug(f"Successfully sent {len(events_to_send)} events from {self.name}")
                else:
                    logger.error(f"Failed to send events from {self.name}: {response.status_code}")
                    # Put events back in buffer for retry
                    self.event_buffer.extend(events_to_send)
                    
        except Exception as e:
            logger.error(f"Error sending events from {self.name}: {e}")
            # Put events back in buffer for retry
            self.event_buffer.extend(events_to_send)
    
    def extract_ip_addresses(self, text: str) -> List[str]:
        """Extract IP addresses from text"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return re.findall(ip_pattern, text)
    
    def extract_domains(self, text: str) -> List[str]:
        """Extract domain names from text"""
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        return re.findall(domain_pattern, text)
    
    def parse_timestamp(self, timestamp_str: str, format_str: str = None) -> Optional[datetime]:
        """Parse timestamp from string"""
        if not timestamp_str:
            return None
            
        # Common timestamp formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%b %d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",
        ]
        
        if format_str:
            formats.insert(0, format_str)
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str.strip(), fmt)
            except ValueError:
                continue
        
        logger.warning(f"Could not parse timestamp: {timestamp_str}")
        return None
    
    def determine_severity(self, event_type: str, message: str) -> SeverityLevel:
        """Determine event severity based on type and content"""
        message_lower = message.lower()
        
        # Critical severity indicators
        critical_keywords = [
            'critical', 'emergency', 'panic', 'fatal', 'exploit', 'malware',
            'ransomware', 'breach', 'compromise', 'intrusion', 'attack'
        ]
        
        # High severity indicators
        high_keywords = [
            'error', 'fail', 'denied', 'unauthorized', 'suspicious', 'threat',
            'virus', 'trojan', 'backdoor', 'rootkit'
        ]
        
        # Medium severity indicators
        medium_keywords = [
            'warning', 'warn', 'unusual', 'anomaly', 'blocked', 'quarantine'
        ]
        
        if any(keyword in message_lower for keyword in critical_keywords):
            return SeverityLevel.CRITICAL
        elif any(keyword in message_lower for keyword in high_keywords):
            return SeverityLevel.HIGH
        elif any(keyword in message_lower for keyword in medium_keywords):
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def determine_event_type(self, message: str, source_system: str = None) -> EventType:
        """Determine event type based on message content and source"""
        message_lower = message.lower()
        
        # Login/Authentication events
        if any(keyword in message_lower for keyword in ['login', 'logon', 'authenticate', 'sign in']):
            if any(keyword in message_lower for keyword in ['fail', 'denied', 'invalid', 'incorrect']):
                return EventType.FAILED_LOGIN
            else:
                return EventType.LOGIN
        
        if any(keyword in message_lower for keyword in ['logout', 'logoff', 'sign out']):
            return EventType.LOGOUT
        
        # File access events
        if any(keyword in message_lower for keyword in ['file', 'read', 'write', 'delete', 'access']):
            return EventType.FILE_ACCESS
        
        # Network events
        if any(keyword in message_lower for keyword in ['connection', 'connect', 'network', 'tcp', 'udp']):
            return EventType.NETWORK_CONNECTION
        
        # Process events
        if any(keyword in message_lower for keyword in ['process', 'execute', 'run', 'start', 'launch']):
            return EventType.PROCESS_EXECUTION
        
        # Security events
        if any(keyword in message_lower for keyword in ['malware', 'virus', 'trojan', 'threat']):
            return EventType.MALWARE_DETECTION
        
        if any(keyword in message_lower for keyword in ['intrusion', 'attack', 'exploit', 'breach']):
            return EventType.INTRUSION_ATTEMPT
        
        if any(keyword in message_lower for keyword in ['privilege', 'escalation', 'admin', 'root', 'sudo']):
            return EventType.PRIVILEGE_ESCALATION
        
        if any(keyword in message_lower for keyword in ['exfiltration', 'data', 'transfer', 'upload']):
            return EventType.DATA_EXFILTRATION
        
        if any(keyword in message_lower for keyword in ['anomaly', 'unusual', 'abnormal']):
            return EventType.SYSTEM_ANOMALY
        
        if any(keyword in message_lower for keyword in ['config', 'configuration', 'setting', 'change']):
            return EventType.CONFIGURATION_CHANGE
        
        # Default to system anomaly for unclassified events
        return EventType.SYSTEM_ANOMALY