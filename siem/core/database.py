from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
import redis
from elasticsearch import Elasticsearch
from typing import Generator
import asyncio
import aioredis

from .config import get_settings

settings = get_settings()

# PostgreSQL Database
engine = create_engine(
    settings.database_url,
    poolclass=StaticPool,
    pool_pre_ping=True,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redis Connection
redis_client = redis.from_url(settings.redis_url, decode_responses=True)

# Elasticsearch Connection
es_client = Elasticsearch([settings.elasticsearch_url])


def get_db() -> Generator[Session, None, None]:
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_redis():
    """Get Redis client"""
    return redis_client


def get_elasticsearch():
    """Get Elasticsearch client"""
    return es_client


async def get_async_redis():
    """Get async Redis client"""
    return await aioredis.from_url(settings.redis_url)


def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)


def init_elasticsearch():
    """Initialize Elasticsearch indices"""
    # Security Events Index
    security_events_mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "source_ip": {"type": "ip"},
                "destination_ip": {"type": "ip"},
                "source_port": {"type": "integer"},
                "destination_port": {"type": "integer"},
                "protocol": {"type": "keyword"},
                "event_type": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "message": {"type": "text", "analyzer": "standard"},
                "raw_log": {"type": "text"},
                "parsed_fields": {"type": "object"},
                "source_system": {"type": "keyword"},
                "user": {"type": "keyword"},
                "process": {"type": "keyword"},
                "file_path": {"type": "keyword"},
                "command": {"type": "text"},
                "tags": {"type": "keyword"},
                "correlation_id": {"type": "keyword"},
                "geolocation": {
                    "properties": {
                        "country": {"type": "keyword"},
                        "city": {"type": "keyword"},
                        "lat": {"type": "float"},
                        "lon": {"type": "float"}
                    }
                }
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.refresh_interval": "1s"
        }
    }
    
    # Create indices if they don't exist
    indices = [
        ("security-events", security_events_mapping),
        ("alerts", security_events_mapping),
        ("threats", security_events_mapping)
    ]
    
    for index_name, mapping in indices:
        if not es_client.indices.exists(index=index_name):
            es_client.indices.create(index=index_name, body=mapping)
            print(f"Created Elasticsearch index: {index_name}")


def check_connections():
    """Check all database connections"""
    try:
        # Test PostgreSQL
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        print("✓ PostgreSQL connection successful")
        
        # Test Redis
        redis_client.ping()
        print("✓ Redis connection successful")
        
        # Test Elasticsearch
        if es_client.ping():
            print("✓ Elasticsearch connection successful")
        else:
            print("✗ Elasticsearch connection failed")
            
    except Exception as e:
        print(f"Database connection error: {e}")
        raise