#!/usr/bin/env python3
"""
SIEM Log Collector Service

This service runs various log collectors to gather security events
from different sources and forward them to the SIEM API.
"""

import asyncio
import signal
import sys
import yaml
import os
from pathlib import Path
from typing import Dict, Any, List
from loguru import logger

from siem.collectors.syslog_collector import SyslogCollector
from siem.collectors.file_collector import FileCollector


class CollectorManager:
    """Manages multiple log collectors"""
    
    def __init__(self, config_path: str = "config/collectors.yaml"):
        self.config_path = config_path
        self.collectors = []
        self.running = False
        
        # Setup logging
        logger.add(
            "logs/collector.log",
            rotation="100 MB",
            retention="30 days",
            level="INFO",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}"
        )
        
        # Load configuration
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load collector configuration"""
        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return self._get_default_config()
            
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            logger.info(f"Loaded configuration from {self.config_path}")
            return config
            
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            logger.info("Using default configuration")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default collector configuration"""
        return {
            "collectors": {
                "syslog": {
                    "enabled": True,
                    "host": "0.0.0.0",
                    "port": 514,
                    "protocol": "udp",
                    "api_url": os.getenv("SIEM_API_URL", "http://localhost:8000"),
                    "batch_size": 100,
                    "flush_interval": 5
                },
                "file": {
                    "enabled": True,
                    "watch_paths": ["/var/log", "/host/var/log"],
                    "file_patterns": ["*.log", "*.txt"],
                    "exclude_patterns": ["*.gz", "*.zip", "*.bz2"],
                    "api_url": os.getenv("SIEM_API_URL", "http://localhost:8000"),
                    "batch_size": 100,
                    "flush_interval": 5
                }
            }
        }
    
    def _create_collectors(self):
        """Create collector instances based on configuration"""
        collector_configs = self.config.get("collectors", {})
        
        # Create syslog collector
        if collector_configs.get("syslog", {}).get("enabled", False):
            try:
                syslog_config = collector_configs["syslog"]
                syslog_collector = SyslogCollector(syslog_config)
                self.collectors.append(syslog_collector)
                logger.info("Created syslog collector")
            except Exception as e:
                logger.error(f"Failed to create syslog collector: {e}")
        
        # Create file collector
        if collector_configs.get("file", {}).get("enabled", False):
            try:
                file_config = collector_configs["file"]
                file_collector = FileCollector(file_config)
                self.collectors.append(file_collector)
                logger.info("Created file collector")
            except Exception as e:
                logger.error(f"Failed to create file collector: {e}")
        
        logger.info(f"Created {len(self.collectors)} collectors")
    
    async def start(self):
        """Start all collectors"""
        logger.info("Starting SIEM Collector Manager")
        
        # Create collectors
        self._create_collectors()
        
        if not self.collectors:
            logger.error("No collectors configured or enabled")
            return
        
        self.running = True
        
        # Start all collectors
        tasks = []
        for collector in self.collectors:
            task = asyncio.create_task(collector.start())
            tasks.append(task)
        
        try:
            # Wait for all collectors to complete
            await asyncio.gather(*tasks)
        except Exception as e:
            logger.error(f"Error in collector manager: {e}")
        finally:
            self.running = False
    
    async def stop(self):
        """Stop all collectors"""
        logger.info("Stopping SIEM Collector Manager")
        self.running = False
        
        # Stop all collectors
        for collector in self.collectors:
            try:
                await collector.stop()
            except Exception as e:
                logger.error(f"Error stopping collector {collector.name}: {e}")
        
        logger.info("All collectors stopped")


async def main():
    """Main entry point"""
    # Setup signal handlers
    manager = CollectorManager()
    
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(manager.stop())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await manager.start()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        await manager.stop()


if __name__ == "__main__":
    # Create necessary directories
    os.makedirs("logs", exist_ok=True)
    os.makedirs("config", exist_ok=True)
    
    # Run the collector manager
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)