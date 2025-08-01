import asyncio
import os
import re
from datetime import datetime
from typing import Dict, Any, Optional, AsyncGenerator, Set
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import aiofiles
from loguru import logger

from .base_collector import BaseCollector
from siem.models.events import SecurityEventCreate, EventType, SeverityLevel


class FileWatcher(FileSystemEventHandler):
    """File system event handler for log file monitoring"""
    
    def __init__(self, collector):
        self.collector = collector
        super().__init__()
    
    def on_modified(self, event):
        if not event.is_directory:
            self.collector.add_modified_file(event.src_path)


class FileCollector(BaseCollector):
    """File collector for monitoring log files"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("file", config)
        self.watch_paths = config.get("watch_paths", ["/var/log"])
        self.file_patterns = config.get("file_patterns", ["*.log", "*.txt"])
        self.exclude_patterns = config.get("exclude_patterns", ["*.gz", "*.zip"])
        self.max_line_length = config.get("max_line_length", 8192)
        self.encoding = config.get("encoding", "utf-8")
        
        # Track file positions to avoid re-reading
        self.file_positions = {}
        self.modified_files = asyncio.Queue()
        self.observer = None
        self.watched_files: Set[str] = set()
    
    async def collect_events(self) -> AsyncGenerator[str, None]:
        """Collect events from log files"""
        try:
            # Start file system watcher
            self.observer = Observer()
            file_watcher = FileWatcher(self)
            
            # Watch specified directories
            for watch_path in self.watch_paths:
                if os.path.exists(watch_path):
                    self.observer.schedule(file_watcher, watch_path, recursive=True)
                    logger.info(f"Watching directory: {watch_path}")
                else:
                    logger.warning(f"Watch path does not exist: {watch_path}")
            
            self.observer.start()
            
            # Initial scan of existing files
            await self._initial_scan()
            
            # Process file modifications
            while self.running:
                try:
                    # Wait for file modifications
                    file_path = await asyncio.wait_for(
                        self.modified_files.get(),
                        timeout=1.0
                    )
                    
                    # Read new lines from modified file
                    async for line in self._read_file_lines(file_path):
                        yield line
                        
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"Error processing file modifications: {e}")
                    await asyncio.sleep(1)
                    
        except Exception as e:
            logger.error(f"Error in file collector: {e}")
        finally:
            if self.observer:
                self.observer.stop()
                self.observer.join()
    
    async def _initial_scan(self):
        """Initial scan of existing log files"""
        for watch_path in self.watch_paths:
            if not os.path.exists(watch_path):
                continue
                
            try:
                for file_path in Path(watch_path).rglob("*"):
                    if file_path.is_file() and self._should_monitor_file(str(file_path)):
                        self.watched_files.add(str(file_path))
                        # Read last few lines from existing files
                        await self._read_file_tail(str(file_path))
                        
            except Exception as e:
                logger.error(f"Error during initial scan of {watch_path}: {e}")
    
    def add_modified_file(self, file_path: str):
        """Add modified file to processing queue"""
        if self._should_monitor_file(file_path):
            try:
                self.modified_files.put_nowait(file_path)
            except asyncio.QueueFull:
                logger.warning(f"File modification queue full, dropping: {file_path}")
    
    def _should_monitor_file(self, file_path: str) -> bool:
        """Check if file should be monitored"""
        file_path_obj = Path(file_path)
        
        # Check if file matches include patterns
        matches_pattern = any(
            file_path_obj.match(pattern) for pattern in self.file_patterns
        )
        
        if not matches_pattern:
            return False
        
        # Check if file matches exclude patterns
        matches_exclude = any(
            file_path_obj.match(pattern) for pattern in self.exclude_patterns
        )
        
        return not matches_exclude
    
    async def _read_file_tail(self, file_path: str, lines: int = 10):
        """Read last N lines from file"""
        try:
            async with aiofiles.open(file_path, 'r', encoding=self.encoding, errors='ignore') as f:
                # Read all lines and take the last N
                all_lines = await f.readlines()
                tail_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
                
                # Update file position
                await f.seek(0, 2)  # Seek to end
                self.file_positions[file_path] = await f.tell()
                
                # Process tail lines
                for line in tail_lines:
                    line = line.strip()
                    if line and len(line) <= self.max_line_length:
                        # Add file path context to the line
                        yield f"[{file_path}] {line}"
                        
        except Exception as e:
            logger.error(f"Error reading file tail {file_path}: {e}")
    
    async def _read_file_lines(self, file_path: str) -> AsyncGenerator[str, None]:
        """Read new lines from file since last position"""
        try:
            async with aiofiles.open(file_path, 'r', encoding=self.encoding, errors='ignore') as f:
                # Seek to last known position
                last_position = self.file_positions.get(file_path, 0)
                await f.seek(last_position)
                
                # Read new lines
                while True:
                    line = await f.readline()
                    if not line:
                        break
                    
                    line = line.strip()
                    if line and len(line) <= self.max_line_length:
                        # Add file path context to the line
                        yield f"[{file_path}] {line}"
                
                # Update file position
                self.file_positions[file_path] = await f.tell()
                
        except Exception as e:
            logger.error(f"Error reading file lines {file_path}: {e}")
    
    def parse_event(self, raw_event: str) -> Optional[SecurityEventCreate]:
        """Parse log file line into SecurityEvent"""
        try:
            # Extract file path from context
            file_path_match = re.match(r'^\[([^\]]+)\]\s*(.*)$', raw_event)
            if file_path_match:
                file_path, message = file_path_match.groups()
                raw_log = message
            else:
                file_path = "unknown"
                message = raw_event
                raw_log = raw_event
            
            if not message.strip():
                return None
            
            # Try to parse common log formats
            parsed_event = self._parse_common_formats(message, file_path, raw_log)
            if parsed_event:
                return parsed_event
            
            # Fallback: create generic event
            event_type = self.determine_event_type(message)
            severity = self.determine_severity(event_type.value, message)
            
            parsed_fields = {
                "file_path": file_path,
                "log_format": "unknown"
            }
            
            # Extract IP addresses
            ip_addresses = self.extract_ip_addresses(message)
            if ip_addresses:
                parsed_fields["ip_addresses"] = ip_addresses
            
            return SecurityEventCreate(
                event_type=event_type,
                severity=severity,
                message=message,
                raw_log=raw_log,
                source_system="file",
                file_path=file_path,
                parsed_fields=parsed_fields,
                tags=["file_log", Path(file_path).stem]
            )
            
        except Exception as e:
            logger.error(f"Error parsing file event: {e}")
            logger.debug(f"Raw event: {raw_event}")
            return None
    
    def _parse_common_formats(self, message: str, file_path: str, raw_log: str) -> Optional[SecurityEventCreate]:
        """Parse common log formats"""
        
        # Apache/Nginx access log format
        apache_pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*)" (\d+) (\d+|-) "([^"]*)" "([^"]*)"'
        apache_match = re.match(apache_pattern, message)
        if apache_match:
            return self._parse_apache_log(apache_match, file_path, raw_log)
        
        # Common syslog format (already handled in syslog collector, but might appear in files)
        syslog_pattern = r'^(.{15})\s+(\S+)\s+([^:]+):\s*(.*)$'
        syslog_match = re.match(syslog_pattern, message)
        if syslog_match:
            return self._parse_syslog_format(syslog_match, file_path, raw_log)
        
        # JSON log format
        if message.strip().startswith('{') and message.strip().endswith('}'):
            return self._parse_json_log(message, file_path, raw_log)
        
        # Windows Event Log format
        windows_pattern = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)\s+(\d+)\s+(.*)$'
        windows_match = re.match(windows_pattern, message)
        if windows_match:
            return self._parse_windows_log(windows_match, file_path, raw_log)
        
        return None
    
    def _parse_apache_log(self, match, file_path: str, raw_log: str) -> SecurityEventCreate:
        """Parse Apache/Nginx access log"""
        ip, timestamp_str, method, url, status, size, referer, user_agent = match.groups()
        
        timestamp = self.parse_timestamp(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        status_code = int(status)
        
        # Determine event type and severity based on status code
        if status_code >= 400:
            if status_code == 401:
                event_type = EventType.FAILED_LOGIN
                severity = SeverityLevel.MEDIUM
            elif status_code in [403, 404]:
                event_type = EventType.INTRUSION_ATTEMPT
                severity = SeverityLevel.LOW
            elif status_code >= 500:
                event_type = EventType.SYSTEM_ANOMALY
                severity = SeverityLevel.HIGH
            else:
                event_type = EventType.NETWORK_CONNECTION
                severity = SeverityLevel.LOW
        else:
            event_type = EventType.NETWORK_CONNECTION
            severity = SeverityLevel.LOW
        
        parsed_fields = {
            "method": method,
            "url": url,
            "status_code": status_code,
            "response_size": size,
            "referer": referer,
            "user_agent": user_agent,
            "log_format": "apache"
        }
        
        return SecurityEventCreate(
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source_ip=ip,
            message=f"{method} {url} - {status}",
            raw_log=raw_log,
            source_system="file",
            file_path=file_path,
            parsed_fields=parsed_fields,
            tags=["web_access", "apache"]
        )
    
    def _parse_syslog_format(self, match, file_path: str, raw_log: str) -> SecurityEventCreate:
        """Parse syslog format in file"""
        timestamp_str, hostname, tag, message = match.groups()
        
        timestamp = self.parse_timestamp(timestamp_str, "%b %d %H:%M:%S")
        if timestamp and timestamp.year == 1900:
            timestamp = timestamp.replace(year=datetime.now().year)
        
        event_type = self.determine_event_type(message, tag)
        severity = self.determine_severity(event_type.value, message)
        
        parsed_fields = {
            "hostname": hostname,
            "tag": tag,
            "log_format": "syslog"
        }
        
        return SecurityEventCreate(
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            message=message,
            raw_log=raw_log,
            source_system="file",
            process=tag,
            file_path=file_path,
            parsed_fields=parsed_fields,
            tags=["syslog", tag]
        )
    
    def _parse_json_log(self, message: str, file_path: str, raw_log: str) -> Optional[SecurityEventCreate]:
        """Parse JSON log format"""
        try:
            import json
            log_data = json.loads(message)
            
            # Extract common fields
            timestamp_str = log_data.get('timestamp') or log_data.get('time') or log_data.get('@timestamp')
            level = log_data.get('level') or log_data.get('severity')
            msg = log_data.get('message') or log_data.get('msg') or str(log_data)
            
            timestamp = None
            if timestamp_str:
                timestamp = self.parse_timestamp(str(timestamp_str))
            
            # Map log level to severity
            severity_map = {
                'debug': SeverityLevel.LOW,
                'info': SeverityLevel.LOW,
                'warn': SeverityLevel.MEDIUM,
                'warning': SeverityLevel.MEDIUM,
                'error': SeverityLevel.HIGH,
                'fatal': SeverityLevel.CRITICAL,
                'critical': SeverityLevel.CRITICAL
            }
            
            severity = severity_map.get(str(level).lower(), SeverityLevel.LOW)
            event_type = self.determine_event_type(msg)
            
            parsed_fields = log_data.copy()
            parsed_fields["log_format"] = "json"
            
            return SecurityEventCreate(
                timestamp=timestamp,
                event_type=event_type,
                severity=severity,
                message=msg,
                raw_log=raw_log,
                source_system="file",
                file_path=file_path,
                parsed_fields=parsed_fields,
                tags=["json_log", level] if level else ["json_log"]
            )
            
        except Exception as e:
            logger.error(f"Error parsing JSON log: {e}")
            return None
    
    def _parse_windows_log(self, match, file_path: str, raw_log: str) -> SecurityEventCreate:
        """Parse Windows event log format"""
        timestamp_str, level, event_id, message = match.groups()
        
        timestamp = self.parse_timestamp(timestamp_str, "%Y-%m-%d %H:%M:%S")
        
        # Map Windows log levels
        level_map = {
            'Error': SeverityLevel.HIGH,
            'Warning': SeverityLevel.MEDIUM,
            'Information': SeverityLevel.LOW,
            'Critical': SeverityLevel.CRITICAL
        }
        
        severity = level_map.get(level, SeverityLevel.LOW)
        event_type = self.determine_event_type(message)
        
        parsed_fields = {
            "event_id": int(event_id),
            "level": level,
            "log_format": "windows"
        }
        
        return SecurityEventCreate(
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            message=message,
            raw_log=raw_log,
            source_system="file",
            file_path=file_path,
            parsed_fields=parsed_fields,
            tags=["windows_log", level.lower()]
        )