import asyncio
import re
import socket
from datetime import datetime
from typing import Dict, Any, Optional, AsyncGenerator
from loguru import logger

from .base_collector import BaseCollector
from siem.models.events import SecurityEventCreate, EventType, SeverityLevel


class SyslogCollector(BaseCollector):
    """Syslog collector for system logs"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("syslog", config)
        self.host = config.get("host", "0.0.0.0")
        self.port = config.get("port", 514)
        self.protocol = config.get("protocol", "udp").lower()
        self.buffer_size = config.get("buffer_size", 4096)
        
        # Syslog facility and severity mappings
        self.facilities = {
            0: "kernel", 1: "user", 2: "mail", 3: "daemon", 4: "security",
            5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
            10: "authpriv", 11: "ftp", 16: "local0", 17: "local1",
            18: "local2", 19: "local3", 20: "local4", 21: "local5",
            22: "local6", 23: "local7"
        }
        
        self.severities = {
            0: "emergency", 1: "alert", 2: "critical", 3: "error",
            4: "warning", 5: "notice", 6: "info", 7: "debug"
        }
    
    async def collect_events(self) -> AsyncGenerator[str, None]:
        """Collect syslog events via UDP/TCP"""
        if self.protocol == "udp":
            async for event in self._collect_udp():
                yield event
        elif self.protocol == "tcp":
            async for event in self._collect_tcp():
                yield event
        else:
            logger.error(f"Unsupported protocol: {self.protocol}")
    
    async def _collect_udp(self) -> AsyncGenerator[str, None]:
        """Collect syslog events via UDP"""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.setblocking(False)
            
            logger.info(f"Syslog collector listening on UDP {self.host}:{self.port}")
            
            while self.running:
                try:
                    # Use asyncio to make socket non-blocking
                    loop = asyncio.get_event_loop()
                    data, addr = await loop.sock_recvfrom(sock, self.buffer_size)
                    
                    if data:
                        message = data.decode('utf-8', errors='ignore').strip()
                        if message:
                            yield message
                            
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error receiving UDP syslog: {e}")
                    await asyncio.sleep(1)
                    
        except Exception as e:
            logger.error(f"Error setting up UDP syslog collector: {e}")
        finally:
            if 'sock' in locals():
                sock.close()
    
    async def _collect_tcp(self) -> AsyncGenerator[str, None]:
        """Collect syslog events via TCP"""
        try:
            server = await asyncio.start_server(
                self._handle_tcp_client,
                self.host,
                self.port
            )
            
            logger.info(f"Syslog collector listening on TCP {self.host}:{self.port}")
            
            async with server:
                await server.serve_forever()
                
        except Exception as e:
            logger.error(f"Error setting up TCP syslog collector: {e}")
    
    async def _handle_tcp_client(self, reader, writer):
        """Handle TCP client connection"""
        client_addr = writer.get_extra_info('peername')
        logger.debug(f"New TCP syslog connection from {client_addr}")
        
        try:
            while self.running:
                data = await reader.readline()
                if not data:
                    break
                    
                message = data.decode('utf-8', errors='ignore').strip()
                if message:
                    # Process the message (you'd need to implement a queue here)
                    parsed_event = self.parse_event(message)
                    if parsed_event:
                        self.event_buffer.append(parsed_event)
                        
        except Exception as e:
            logger.error(f"Error handling TCP syslog client {client_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    def parse_event(self, raw_event: str) -> Optional[SecurityEventCreate]:
        """Parse syslog message into SecurityEvent"""
        try:
            # Parse RFC3164 syslog format: <priority>timestamp hostname tag: message
            syslog_pattern = r'^<(\d+)>(.{15})\s+(\S+)\s+([^:]+):\s*(.*)$'
            match = re.match(syslog_pattern, raw_event)
            
            if not match:
                # Try simplified format without priority
                simple_pattern = r'^(.{15})\s+(\S+)\s+([^:]+):\s*(.*)$'
                simple_match = re.match(simple_pattern, raw_event)
                
                if simple_match:
                    timestamp_str, hostname, tag, message = simple_match.groups()
                    priority = 30  # Default priority (daemon.info)
                else:
                    # Fallback: treat entire message as content
                    return SecurityEventCreate(
                        event_type=self.determine_event_type(raw_event),
                        severity=self.determine_severity("", raw_event),
                        message=raw_event,
                        raw_log=raw_event,
                        source_system="syslog",
                        parsed_fields={"unparsed": True}
                    )
            else:
                priority, timestamp_str, hostname, tag, message = match.groups()
                priority = int(priority)
            
            # Parse priority to get facility and severity
            facility = priority >> 3
            syslog_severity = priority & 0x07
            
            # Parse timestamp
            timestamp = self.parse_timestamp(timestamp_str, "%b %d %H:%M:%S")
            if timestamp and timestamp.year == 1900:
                # Add current year if not specified
                timestamp = timestamp.replace(year=datetime.now().year)
            
            # Determine event type and severity
            event_type = self.determine_event_type(message, tag)
            severity = self._map_syslog_severity(syslog_severity)
            
            # Extract additional fields
            parsed_fields = {
                "facility": self.facilities.get(facility, f"unknown_{facility}"),
                "syslog_severity": self.severities.get(syslog_severity, f"unknown_{syslog_severity}"),
                "hostname": hostname,
                "tag": tag,
                "priority": priority
            }
            
            # Extract IP addresses and other indicators
            ip_addresses = self.extract_ip_addresses(message)
            if ip_addresses:
                parsed_fields["ip_addresses"] = ip_addresses
                # Use first IP as source_ip if available
                source_ip = ip_addresses[0] if ip_addresses else None
            else:
                source_ip = None
            
            # Extract user information
            user = self._extract_user(message)
            
            # Extract process information
            process = self._extract_process(tag, message)
            
            return SecurityEventCreate(
                timestamp=timestamp,
                event_type=event_type,
                severity=severity,
                source_ip=source_ip,
                user=user,
                process=process,
                message=message,
                raw_log=raw_event,
                parsed_fields=parsed_fields,
                source_system="syslog",
                tags=[tag, self.facilities.get(facility, "unknown")]
            )
            
        except Exception as e:
            logger.error(f"Error parsing syslog event: {e}")
            logger.debug(f"Raw event: {raw_event}")
            return None
    
    def _map_syslog_severity(self, syslog_severity: int) -> SeverityLevel:
        """Map syslog severity to SIEM severity"""
        if syslog_severity <= 2:  # emergency, alert, critical
            return SeverityLevel.CRITICAL
        elif syslog_severity == 3:  # error
            return SeverityLevel.HIGH
        elif syslog_severity == 4:  # warning
            return SeverityLevel.MEDIUM
        else:  # notice, info, debug
            return SeverityLevel.LOW
    
    def _extract_user(self, message: str) -> Optional[str]:
        """Extract username from syslog message"""
        # Common patterns for user extraction
        patterns = [
            r'user\s+([^\s]+)',
            r'for\s+user\s+([^\s]+)',
            r'USER=([^\s]+)',
            r'user=([^\s]+)',
            r'from\s+user\s+([^\s]+)',
            r'by\s+user\s+([^\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_process(self, tag: str, message: str) -> Optional[str]:
        """Extract process information from syslog"""
        # Tag often contains process name and PID
        process_match = re.match(r'^([^\[\(]+)(?:\[(\d+)\]|\((\d+)\))?', tag)
        if process_match:
            process_name = process_match.group(1)
            pid = process_match.group(2) or process_match.group(3)
            if pid:
                return f"{process_name}[{pid}]"
            else:
                return process_name
        
        return tag if tag else None