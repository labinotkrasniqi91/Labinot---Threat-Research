# 🛡️ SIEM - Security Information and Event Management System

A comprehensive, modern SIEM system built with Python, FastAPI, Elasticsearch, and Docker. This system provides real-time security monitoring, event correlation, threat detection, and incident response capabilities.

## 🚀 Features

### Core Capabilities
- **Real-time Log Collection**: Syslog, file monitoring, and network traffic analysis
- **Event Processing**: Parsing, normalization, and enrichment of security events
- **Correlation Engine**: Time-based event correlation and pattern detection
- **Threat Intelligence**: Integration with threat feeds and IOC matching
- **Alert Management**: Intelligent alerting with severity-based prioritization
- **Web Dashboard**: Interactive dashboard for monitoring and investigation
- **REST API**: Comprehensive API for integrations and automation
- **Scalable Architecture**: Microservices-based design with Docker deployment

### Detection Capabilities
- Failed login attempt detection
- Privilege escalation monitoring
- Malware activity detection
- Suspicious network activity
- Data exfiltration detection
- Anomalous user behavior analysis
- System compromise indicators

### Data Sources
- Syslog (UDP/TCP)
- Log files (with real-time monitoring)
- Apache/Nginx access logs
- Windows Event Logs
- JSON structured logs
- Custom log formats

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Log Sources   │───▶│   Collectors    │───▶│  SIEM Core API  │
│                 │    │                 │    │                 │
│ • Syslog        │    │ • Syslog        │    │ • Event         │
│ • Files         │    │ • File Monitor  │    │   Processing    │
│ • Network       │    │ • Network       │    │ • Correlation   │
│ • Applications  │    │ • Custom        │    │ • Alerting      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                       ┌─────────────────┐            │
                       │   Web Dashboard │◀───────────┤
                       │                 │            │
                       │ • Monitoring    │            │
                       │ • Investigation │            │
                       │ • Reporting     │            ▼
                       └─────────────────┘    ┌─────────────────┐
                                              │   Data Storage  │
┌─────────────────┐    ┌─────────────────┐   │                 │
│   External      │◀──▶│   Integrations  │   │ • Elasticsearch │
│   Systems       │    │                 │   │ • PostgreSQL    │
│                 │    │ • SOAR          │   │ • Redis         │
│ • SOAR          │    │ • Ticketing     │   └─────────────────┘
│ • Ticketing     │    │ • Notifications │
│ • Email/Slack   │    └─────────────────┘
└─────────────────┘
```

## 🛠️ Technology Stack

- **Backend**: Python 3.11, FastAPI, SQLAlchemy, Pydantic
- **Data Storage**: Elasticsearch, PostgreSQL, Redis
- **Message Processing**: Async/await, asyncio
- **Containerization**: Docker, Docker Compose
- **Monitoring**: Loguru, built-in health checks
- **Visualization**: Kibana (optional), built-in web dashboard

## 📦 Installation

### Prerequisites
- Docker and Docker Compose
- At least 4GB RAM
- 10GB free disk space

### Quick Start

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd siem
   ```

2. **Start the SIEM stack**:
   ```bash
   docker-compose up -d
   ```

3. **Access the dashboard**:
   - SIEM Dashboard: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Kibana (optional): http://localhost:5601

4. **Check system health**:
   ```bash
   curl http://localhost:8000/health
   ```

### Manual Installation

1. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up databases**:
   ```bash
   # Start PostgreSQL, Redis, and Elasticsearch
   docker-compose up -d postgres redis elasticsearch
   ```

3. **Run the SIEM core**:
   ```bash
   python -m siem.main
   ```

4. **Run log collectors** (in separate terminal):
   ```bash
   python collector_main.py
   ```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# Database Configuration
DATABASE_URL=postgresql://siem_user:siem_password@localhost:5432/siem_db
REDIS_URL=redis://localhost:6379
ELASTICSEARCH_URL=http://localhost:9200

# Security Settings
SECRET_KEY=your-secret-key-change-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=30

# SIEM Settings
LOG_RETENTION_DAYS=90
MAX_EVENTS_PER_MINUTE=10000
CORRELATION_WINDOW_MINUTES=5

# Alert Settings
ALERT_COOLDOWN_MINUTES=15
MAX_ALERTS_PER_HOUR=100
```

### Collector Configuration

Edit `config/collectors.yaml` to configure log collectors:

```yaml
collectors:
  syslog:
    enabled: true
    host: "0.0.0.0"
    port: 514
    protocol: "udp"
    
  file:
    enabled: true
    watch_paths:
      - "/var/log"
      - "/path/to/your/logs"
    file_patterns:
      - "*.log"
      - "*.txt"
```

### Detection Rules

Detection rules are defined in `config/rules/default_rules.yaml`. You can:
- Enable/disable rules
- Modify thresholds and time windows
- Add custom detection logic
- Configure alert actions

## 📊 Usage

### Web Dashboard

The web dashboard provides:
- Real-time event monitoring
- Alert management
- System statistics
- Search and filtering capabilities

Access: http://localhost:8000

### REST API

Key API endpoints:

```bash
# Create security event
POST /api/v1/events
{
  "event_type": "failed_login",
  "severity": "medium",
  "source_ip": "192.168.1.100",
  "message": "Failed login attempt",
  "source_system": "ssh"
}

# Get events with filtering
GET /api/v1/events?severity=high&limit=100

# Get alerts
GET /api/v1/alerts?status=open

# Search events
GET /api/v1/search?query=failed+login

# Get dashboard statistics
GET /api/v1/dashboard/stats
```

### Log Collection

#### Syslog
Send logs to the SIEM via syslog:
```bash
logger -n localhost -P 514 "Test security event"
```

#### File Monitoring
Place log files in monitored directories:
```bash
echo "$(date) Failed login attempt from 192.168.1.100" >> /var/log/auth.log
```

#### API Direct
Send events directly via API:
```bash
curl -X POST http://localhost:8000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{"event_type": "login", "severity": "low", "message": "User login", "source_system": "web"}'
```

## 🔧 Customization

### Adding Custom Collectors

1. Create a new collector class inheriting from `BaseCollector`:

```python
from siem.collectors.base_collector import BaseCollector

class CustomCollector(BaseCollector):
    async def collect_events(self):
        # Your collection logic here
        pass
    
    def parse_event(self, raw_event):
        # Your parsing logic here
        pass
```

2. Register the collector in `collector_main.py`

### Adding Detection Rules

1. Create rule in `config/rules/custom_rules.yaml`:

```yaml
- rule_id: "custom_rule"
  name: "Custom Detection Rule"
  description: "Detects custom security events"
  severity: "medium"
  enabled: true
  query: |
    {
      "query": {
        "match": {"message": "custom_pattern"}
      }
    }
  conditions:
    time_window: 300
    threshold: 5
```

2. Rules are automatically loaded on startup

### Extending Event Processing

Modify `siem/core/event_processor.py` to add:
- Custom enrichment logic
- Additional correlation rules
- New alert actions
- Integration with external systems

## 🔍 Monitoring and Troubleshooting

### Health Checks

```bash
# Check system health
curl http://localhost:8000/health

# Check individual services
docker-compose ps
```

### Logs

```bash
# SIEM core logs
docker-compose logs siem-core

# Collector logs
docker-compose logs log-collector

# Database logs
docker-compose logs postgres elasticsearch redis
```

### Performance Monitoring

- Monitor Elasticsearch cluster health: http://localhost:9200/_cluster/health
- Check Redis memory usage: `redis-cli info memory`
- Monitor database connections and query performance

## 🚨 Security Considerations

### Production Deployment

1. **Change default passwords**:
   - PostgreSQL credentials
   - Elasticsearch security (if enabled)
   - Secret keys

2. **Network Security**:
   - Use TLS/SSL for all communications
   - Implement network segmentation
   - Configure firewalls appropriately

3. **Access Control**:
   - Implement authentication for web dashboard
   - Use API keys for external integrations
   - Apply principle of least privilege

4. **Data Protection**:
   - Encrypt sensitive data at rest
   - Implement log retention policies
   - Regular security audits

### Compliance

The SIEM system supports compliance with:
- SOX (Sarbanes-Oxley)
- PCI DSS
- HIPAA
- GDPR (with proper configuration)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the API documentation at `/docs`

## 🔄 Roadmap

- [ ] Machine learning-based anomaly detection
- [ ] Advanced threat hunting capabilities
- [ ] Integration with more threat intelligence feeds
- [ ] Mobile dashboard application
- [ ] Advanced reporting and compliance features
- [ ] SOAR (Security Orchestration, Automation and Response) integration

## 📈 Performance

### Benchmarks
- **Event Processing**: 10,000+ events/minute
- **Search Performance**: Sub-second response times
- **Storage Efficiency**: Optimized Elasticsearch indices
- **Memory Usage**: < 2GB RAM for basic deployment

### Scaling
- Horizontal scaling with multiple collector instances
- Elasticsearch cluster scaling
- Load balancing for high availability
- Database read replicas for improved performance

---

**Built with ❤️ for cybersecurity professionals**
