"""
Database configuration for MySQL
"""
import os
from urllib.parse import quote_plus
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Note: .env is loaded in app.py before this module is imported
# Do not load .env here to avoid duplicate loading

# Initialize SQLAlchemy
db = SQLAlchemy()

# Database configuration - REQUIRED environment variables
# Validation is done in configure_database()

def get_database_url():
    """Get MySQL database URL (deprecated)."""
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DB_NAME = os.getenv('DB_NAME')
    
    if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
        raise ValueError("Database environment variables not set")
    
    user = quote_plus(DB_USER)
    password = quote_plus(DB_PASSWORD)
    database = quote_plus(DB_NAME)
    return f"mysql+pymysql://{user}:{password}@{DB_HOST}:{DB_PORT}/{database}?charset=utf8mb4"

def configure_database(app: Flask):
    """Configure Flask app with database."""
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DB_NAME = os.getenv('DB_NAME')
    
    # Validate required database configuration
    if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
        missing = [var for var, val in [
            ('DB_HOST', DB_HOST),
            ('DB_USER', DB_USER),
            ('DB_PASSWORD', DB_PASSWORD),
            ('DB_NAME', DB_NAME)
        ] if not val]
        raise ValueError(
            f"Missing required database environment variables: {', '.join(missing)}. "
            "Please set these in your .env file or environment."
        )
    
    # Build database URL
    user = quote_plus(DB_USER)
    password = quote_plus(DB_PASSWORD)
    database = quote_plus(DB_NAME)

    database_url = f"mysql+pymysql://{user}:{password}@{DB_HOST}:{DB_PORT}/{database}?charset=utf8mb4"
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = os.getenv('DB_ECHO', 'False').lower() == 'true'
    
    # Corrected SQLAlchemy engine options
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': int(os.getenv('DB_POOL_SIZE', 10)),
        'pool_recycle': int(os.getenv('DB_POOL_RECYCLE', 3600)),
        'pool_pre_ping': True,
        'max_overflow': int(os.getenv('DB_MAX_OVERFLOW', 20)),
        'connect_args': {
            'connect_timeout': int(os.getenv('DB_CONNECT_TIMEOUT', 10))
        }
    }
    
    db.init_app(app)
    return db

def test_connection(app: Flask) -> bool:
    """Test database connection."""
    try:
        with app.app_context():
            db.session.execute(db.text('SELECT 1'))
            return True
    except Exception:
        return False

def init_database(app: Flask) -> bool:
    """Initialize database tables."""
    try:
        with app.app_context():
            from models import User, Item, Customer, Quotation, QuotationItem, GstRule, Settings, Log
        return True
    except Exception:
        return False

def get_db_connection_info():
    """Return minimal non-sensitive DB info."""
    return {
        'host': '***',
        'port': int(os.getenv('DB_PORT', 3306)),
        'database': '***',
        'user': '***',
        'password': '***'
    }

__all__ = ['db', 'configure_database', 'init_database', 'test_connection', 'get_database_url', 'get_db_connection_info']
