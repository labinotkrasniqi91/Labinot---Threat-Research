#!/bin/bash

# SIEM System Startup Script
# This script starts the complete SIEM system

set -e

echo "🛡️  Starting SIEM System..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
print_status "Creating directories..."
mkdir -p logs config data static

# Copy example configuration if config doesn't exist
if [ ! -f config/collectors.yaml ]; then
    print_status "Creating default collector configuration..."
    # The config file should already exist from the setup
fi

# Copy example environment file if .env doesn't exist
if [ ! -f .env ]; then
    print_warning "No .env file found. Creating from example..."
    if [ -f .env.example ]; then
        cp .env.example .env
        print_warning "Please edit .env file with your configuration before proceeding."
        echo "Press Enter to continue after editing .env, or Ctrl+C to exit..."
        read
    else
        print_error ".env.example not found. Please create .env file manually."
        exit 1
    fi
fi

# Check if ports are available
check_port() {
    local port=$1
    local service=$2
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        print_warning "Port $port is already in use. $service may conflict."
        return 1
    fi
    return 0
}

print_status "Checking port availability..."
check_port 8000 "SIEM API"
check_port 5432 "PostgreSQL"
check_port 6379 "Redis"
check_port 9200 "Elasticsearch"
check_port 5601 "Kibana"
check_port 514 "Syslog"

# Pull latest images
print_status "Pulling Docker images..."
docker-compose pull

# Start the infrastructure services first
print_status "Starting infrastructure services..."
docker-compose up -d postgres redis elasticsearch

# Wait for services to be ready
print_status "Waiting for infrastructure services to be ready..."
sleep 30

# Check if Elasticsearch is ready
print_status "Checking Elasticsearch health..."
for i in {1..30}; do
    if curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; then
        print_status "Elasticsearch is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "Elasticsearch failed to start within timeout"
        exit 1
    fi
    echo "Waiting for Elasticsearch... ($i/30)"
    sleep 2
done

# Check if PostgreSQL is ready
print_status "Checking PostgreSQL health..."
for i in {1..30}; do
    if docker-compose exec -T postgres pg_isready -U siem_user >/dev/null 2>&1; then
        print_status "PostgreSQL is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "PostgreSQL failed to start within timeout"
        exit 1
    fi
    echo "Waiting for PostgreSQL... ($i/30)"
    sleep 2
done

# Check if Redis is ready
print_status "Checking Redis health..."
for i in {1..30}; do
    if docker-compose exec -T redis redis-cli ping >/dev/null 2>&1; then
        print_status "Redis is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "Redis failed to start within timeout"
        exit 1
    fi
    echo "Waiting for Redis... ($i/30)"
    sleep 2
done

# Start the SIEM application services
print_status "Starting SIEM application services..."
docker-compose up -d siem-core log-collector

# Optionally start Kibana
if [ "${START_KIBANA:-true}" = "true" ]; then
    print_status "Starting Kibana..."
    docker-compose up -d kibana
fi

# Wait for SIEM core to be ready
print_status "Waiting for SIEM core to be ready..."
for i in {1..60}; do
    if curl -s http://localhost:8000/health >/dev/null 2>&1; then
        print_status "SIEM core is ready!"
        break
    fi
    if [ $i -eq 60 ]; then
        print_error "SIEM core failed to start within timeout"
        docker-compose logs siem-core
        exit 1
    fi
    echo "Waiting for SIEM core... ($i/60)"
    sleep 2
done

# Display status
print_status "Checking service status..."
docker-compose ps

# Display access information
echo ""
echo -e "${BLUE}🎉 SIEM System Started Successfully!${NC}"
echo ""
echo "Access URLs:"
echo "  🛡️  SIEM Dashboard:    http://localhost:8000"
echo "  📚 API Documentation: http://localhost:8000/docs"
echo "  📊 Health Check:      http://localhost:8000/health"
if [ "${START_KIBANA:-true}" = "true" ]; then
    echo "  📈 Kibana Dashboard:  http://localhost:5601"
fi
echo ""
echo "System Status:"
curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || echo "  Status check failed"
echo ""

# Show useful commands
echo "Useful commands:"
echo "  📋 View logs:          docker-compose logs -f"
echo "  🔄 Restart services:   docker-compose restart"
echo "  🛑 Stop system:        docker-compose down"
echo "  📊 Service status:     docker-compose ps"
echo ""

# Test log ingestion
print_status "Testing log ingestion..."
echo "Sending test event..."
curl -s -X POST http://localhost:8000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "login",
    "severity": "low",
    "source_ip": "127.0.0.1",
    "message": "Test login event from startup script",
    "source_system": "test"
  }' >/dev/null 2>&1 && print_status "Test event sent successfully!" || print_warning "Failed to send test event"

echo ""
print_status "SIEM system is now running! 🚀"
echo ""