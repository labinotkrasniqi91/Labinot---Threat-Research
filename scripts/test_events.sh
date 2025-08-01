#!/bin/bash

# Test Event Generator for SIEM System
# This script generates various test security events

set -e

SIEM_URL="http://localhost:8000"
API_ENDPOINT="$SIEM_URL/api/v1/events"

echo "🧪 SIEM Test Event Generator"
echo "Sending test events to: $API_ENDPOINT"
echo ""

# Function to send event
send_event() {
    local event_data="$1"
    local description="$2"
    
    echo "📤 Sending: $description"
    
    response=$(curl -s -w "%{http_code}" -X POST "$API_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "$event_data")
    
    http_code="${response: -3}"
    response_body="${response%???}"
    
    if [ "$http_code" -eq 200 ] || [ "$http_code" -eq 201 ]; then
        echo "✅ Success (HTTP $http_code)"
    else
        echo "❌ Failed (HTTP $http_code): $response_body"
    fi
    echo ""
}

# Test 1: Failed Login Attempts (should trigger correlation rule)
echo "🔐 Test 1: Failed Login Attempts"
for i in {1..6}; do
    send_event '{
        "event_type": "failed_login",
        "severity": "medium",
        "source_ip": "192.168.1.100",
        "user": "admin",
        "message": "Failed login attempt #'$i' for user admin",
        "source_system": "ssh",
        "tags": ["authentication", "ssh"]
    }' "Failed login attempt #$i"
    sleep 1
done

# Test 2: Successful Login
send_event '{
    "event_type": "login",
    "severity": "low",
    "source_ip": "192.168.1.50",
    "user": "john.doe",
    "message": "Successful login for user john.doe",
    "source_system": "web",
    "tags": ["authentication", "web"]
}' "Successful login"

# Test 3: Privilege Escalation (should trigger alert)
send_event '{
    "event_type": "privilege_escalation",
    "severity": "critical",
    "source_ip": "192.168.1.75",
    "user": "john.doe",
    "process": "sudo",
    "command": "sudo su -",
    "message": "User john.doe executed sudo su - command",
    "source_system": "linux",
    "tags": ["privilege_escalation", "sudo"]
}' "Privilege escalation attempt"

# Test 4: Malware Detection (should trigger alert)
send_event '{
    "event_type": "malware_detection",
    "severity": "critical",
    "source_ip": "192.168.1.200",
    "file_path": "/tmp/suspicious.exe",
    "process": "suspicious.exe",
    "message": "Malware detected: suspicious.exe in /tmp directory",
    "source_system": "antivirus",
    "tags": ["malware", "critical"]
}' "Malware detection"

# Test 5: Network Connection
send_event '{
    "event_type": "network_connection",
    "severity": "low",
    "source_ip": "192.168.1.150",
    "destination_ip": "8.8.8.8",
    "source_port": 45678,
    "destination_port": 53,
    "protocol": "UDP",
    "message": "DNS query to 8.8.8.8",
    "source_system": "firewall",
    "tags": ["network", "dns"]
}' "Network connection"

# Test 6: Suspicious Network Activity
for port in 22 23 135 139 445 1433 3389; do
    send_event '{
        "event_type": "network_connection",
        "severity": "medium",
        "source_ip": "10.0.0.100",
        "destination_ip": "192.168.1.0",
        "destination_port": '$port',
        "protocol": "TCP",
        "message": "Connection attempt to port '$port' from external IP",
        "source_system": "firewall",
        "tags": ["network", "suspicious"]
    }' "Suspicious connection to port $port"
    sleep 0.5
done

# Test 7: File Access
send_event '{
    "event_type": "file_access",
    "severity": "medium",
    "user": "jane.smith",
    "file_path": "/etc/passwd",
    "message": "User jane.smith accessed /etc/passwd file",
    "source_system": "linux",
    "tags": ["file_access", "sensitive"]
}' "Sensitive file access"

# Test 8: Process Execution
send_event '{
    "event_type": "process_execution",
    "severity": "low",
    "user": "system",
    "process": "backup.sh",
    "command": "/usr/local/bin/backup.sh --full",
    "message": "Scheduled backup process started",
    "source_system": "linux",
    "tags": ["process", "backup"]
}' "Process execution"

# Test 9: Data Exfiltration Attempt
send_event '{
    "event_type": "data_exfiltration",
    "severity": "high",
    "source_ip": "192.168.1.99",
    "user": "contractor",
    "file_path": "/data/confidential/customer_data.csv",
    "message": "Large file transfer detected: customer_data.csv (50MB)",
    "source_system": "dlp",
    "tags": ["data_exfiltration", "confidential"]
}' "Data exfiltration attempt"

# Test 10: System Anomaly
send_event '{
    "event_type": "system_anomaly",
    "severity": "medium",
    "message": "Unusual CPU usage pattern detected (95% for 10 minutes)",
    "source_system": "monitoring",
    "tags": ["anomaly", "performance"]
}' "System anomaly"

# Test 11: Configuration Change
send_event '{
    "event_type": "configuration_change",
    "severity": "medium",
    "user": "admin",
    "message": "Firewall rule modified: Allow port 8080 from any",
    "source_system": "firewall",
    "tags": ["configuration", "firewall"]
}' "Configuration change"

# Test 12: Web Application Events (Apache log format)
send_event '{
    "event_type": "network_connection",
    "severity": "low",
    "source_ip": "203.0.113.45",
    "message": "GET /api/users - 200",
    "raw_log": "203.0.113.45 - - [25/Dec/2024:10:00:00 +0000] \"GET /api/users HTTP/1.1\" 200 1234",
    "source_system": "apache",
    "parsed_fields": {
        "method": "GET",
        "url": "/api/users",
        "status_code": 200,
        "response_size": 1234,
        "user_agent": "Mozilla/5.0"
    },
    "tags": ["web", "api"]
}' "Web API access"

# Test 13: Failed Web Authentication
send_event '{
    "event_type": "failed_login",
    "severity": "medium",
    "source_ip": "198.51.100.10",
    "message": "POST /login - 401",
    "raw_log": "198.51.100.10 - - [25/Dec/2024:10:01:00 +0000] \"POST /login HTTP/1.1\" 401 89",
    "source_system": "apache",
    "parsed_fields": {
        "method": "POST",
        "url": "/login",
        "status_code": 401,
        "response_size": 89
    },
    "tags": ["web", "authentication", "failed"]
}' "Failed web authentication"

echo "🎉 Test event generation completed!"
echo ""
echo "You can now:"
echo "  📊 Check the dashboard: $SIEM_URL"
echo "  🔍 View events: $SIEM_URL/api/v1/events"
echo "  🚨 Check alerts: $SIEM_URL/api/v1/alerts"
echo "  📈 View stats: $SIEM_URL/api/v1/dashboard/stats"
echo ""