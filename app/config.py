"""
Configuration settings for the API Security Scan Framework
"""

import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///api_scanner.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # SQLite-specific configuration for better concurrency
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'connect_args': {
            'timeout': 30,  # SQLite timeout in seconds
            'check_same_thread': False,  # Allow multiple threads
            'isolation_level': None,  # Autocommit mode
        }
    }
    
    # Authentication
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')  # Must be set via environment variable
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 3600))
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
    
    # Security: Require strong password in production
    MIN_PASSWORD_LENGTH = int(os.getenv('MIN_PASSWORD_LENGTH', 8))
    REQUIRE_STRONG_PASSWORD = os.getenv('REQUIRE_STRONG_PASSWORD', 'True').lower() == 'true'
    
    # Slack Configuration
    SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')
    SLACK_CHANNEL = os.getenv('SLACK_CHANNEL', '#security-alerts')
    SLACK_USERNAME = os.getenv('SLACK_USERNAME', 'API Security Scanner')
    
    # OpenAI Configuration
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo')
    
    # Data Directory
    DATA_DIR = os.getenv('DATA_DIR', './data')
    
    # Target API Configuration
    API_PORTAL_URL = os.getenv('API_PORTAL_URL', 'https://your-api-portal-url.com/')
    API_BASE_URL = os.getenv('API_BASE_URL', 'https://your-api-base-url.com/')
    
    # Authorization Configuration
    API_AUTHORIZATION_HEADER = os.getenv('API_AUTHORIZATION_HEADER', '')
    API_AUTHORIZATION_TYPE = os.getenv('API_AUTHORIZATION_TYPE', 'Bearer')  # Bearer, Basic, etc.
    API_HEADERS = os.getenv('API_HEADERS', '{}')  # JSON string of additional headers
    
    # Scanning Configuration
    SCAN_RATE_LIMIT = int(os.getenv('SCAN_RATE_LIMIT', 10))
    MAX_SCAN_DURATION = int(os.getenv('MAX_SCAN_DURATION', 300))
    SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', 60))
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', 5))
    
    # Enhanced Scanning Rules
    SCAN_DEPTH = os.getenv('SCAN_DEPTH', 'standard')  # light, standard, thorough
    SCAN_AGGRESSIVENESS = os.getenv('SCAN_AGGRESSIVENESS', 'medium')  # low, medium, high
    ENABLE_PASSIVE_SCANNING = os.getenv('ENABLE_PASSIVE_SCANNING', 'True').lower() == 'true'
    ENABLE_ACTIVE_SCANNING = os.getenv('ENABLE_ACTIVE_SCANNING', 'True').lower() == 'true'
    ENABLE_AJAX_SPIDER = os.getenv('ENABLE_AJAX_SPIDER', 'True').lower() == 'true'
    
    # Custom Scan Rules
    CUSTOM_SCAN_RULES = os.getenv('CUSTOM_SCAN_RULES', '{}')  # JSON string of custom rules
    EXCLUDED_PATHS = os.getenv('EXCLUDED_PATHS', '/health,/status,/metrics').split(',')
    INCLUDED_PATHS = os.getenv('INCLUDED_PATHS', '').split(',')  # Empty means scan all
    MAX_PARAMETERS_PER_ENDPOINT = int(os.getenv('MAX_PARAMETERS_PER_ENDPOINT', 50))
    
    # Tool-Specific Configuration
    SQLMAP_LEVEL = int(os.getenv('SQLMAP_LEVEL', 3))  # 1-5, higher = more thorough
    SQLMAP_RISK = int(os.getenv('SQLMAP_RISK', 2))   # 1-3, higher = more aggressive
    SQLMAP_THREADS = int(os.getenv('SQLMAP_THREADS', 4))
    SQLMAP_TIMEOUT = int(os.getenv('SQLMAP_TIMEOUT', 30))
    
    NUCLEI_TEMPLATES = os.getenv('NUCLEI_TEMPLATES', 'cves,exposures,misconfiguration')
    NUCLEI_SEVERITY = os.getenv('NUCLEI_SEVERITY', 'low,medium,high,critical')
    NUCLEI_RATE_LIMIT = int(os.getenv('NUCLEI_RATE_LIMIT', 150))
    
    # Enhanced Template System Configuration
    TEMPLATES_DIR = os.getenv('TEMPLATES_DIR', './templates')
    ENABLE_UNIVERSAL_TEMPLATES = os.getenv('ENABLE_UNIVERSAL_TEMPLATES', 'True').lower() == 'true'
    TEMPLATE_CACHE_TTL = int(os.getenv('TEMPLATE_CACHE_TTL', 300))  # 5 minutes
    MAX_TEMPLATE_SIZE = int(os.getenv('MAX_TEMPLATE_SIZE', 1024 * 1024))  # 1MB
    
    # Enhanced Scanning Configuration
    ENABLE_BUSINESS_LOGIC_TESTING = os.getenv('ENABLE_BUSINESS_LOGIC_TESTING', 'True').lower() == 'true'
    ENABLE_API_SPECIFIC_TESTS = os.getenv('ENABLE_API_SPECIFIC_TESTS', 'True').lower() == 'true'
    ENABLE_ADVANCED_PARAMETER_TESTING = os.getenv('ENABLE_ADVANCED_PARAMETER_TESTING', 'True').lower() == 'true'
    TEST_INTENSITY = os.getenv('TEST_INTENSITY', 'standard')  # light, standard, aggressive, comprehensive
    BUSINESS_LOGIC_TEST_DEPTH = os.getenv('BUSINESS_LOGIC_TEST_DEPTH', 'medium')  # basic, medium, advanced
    CUSTOM_TEMPLATES_DIR = os.getenv('CUSTOM_TEMPLATES_DIR', './templates/custom')
    COMMUNITY_TEMPLATES_DIR = os.getenv('COMMUNITY_TEMPLATES_DIR', './templates/community')
    
    ZAP_SPIDER_DEPTH = int(os.getenv('ZAP_SPIDER_DEPTH', 3))
    ZAP_MAX_CHILDREN = int(os.getenv('ZAP_MAX_CHILDREN', 10))
    ZAP_SCAN_POLICY = os.getenv('ZAP_SCAN_POLICY', 'default')
    
    # OWASP ZAP Configuration
    ZAP_API_URL = os.getenv('ZAP_API_URL', 'http://localhost:8080')
    ZAP_API_KEY = os.getenv('ZAP_API_KEY', 'd4e1iq1d6gl4d4sfr0e4eotv2q')  # Default API key for testing
    ZAP_CONTEXT_NAME = os.getenv('ZAP_CONTEXT_NAME', 'api_security_context')  # Use existing context
    ZAP_DAEMON_MODE = os.getenv('ZAP_DAEMON_MODE', 'True').lower() == 'true'
    
    # External Security Tools
    SQLMAP_PATH = os.getenv('SQLMAP_PATH', '/Users/danxzero/Library/Python/3.9/bin/sqlmap')
    SSRFMAP_PATH = os.getenv('SSRFMAP_PATH', './SSRFmap/ssrfmap.py')  # Local installation
    XSSTRIKE_PATH = os.getenv('XSSTRIKE_PATH', '/Users/danxzero/Library/Python/3.9/bin/xsstrike')
    NUCLEI_PATH = os.getenv('NUCLEI_PATH', '/opt/homebrew/bin/nuclei')
    VULNAPI_PATH = os.getenv('VULNAPI_PATH', 'vulnapi')  # Assuming it's in the PATH
    WUPPIEFUZZ_PATH = os.getenv('WUPPIEFUZZ_PATH', 'wuppiefuzz')
    GRAPHQL_COP_PATH = os.getenv('GRAPHQL_COP_PATH', 'graphql-cop.py')
    ZAP_PATH = os.getenv('ZAP_PATH', '/Applications/ZAP.app/Contents/Java/zap.sh')
    
    # Redis Configuration
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
    # Celery Configuration
    CELERY_BROKER_URL = REDIS_URL
    CELERY_RESULT_BACKEND = REDIS_URL
    CELERY_TASK_SOFT_TIME_LIMIT = 300
    CELERY_TASK_TIME_LIMIT = 600
    
    # Monitoring
    ENABLE_METRICS = os.getenv('ENABLE_METRICS', 'True').lower() == 'true'
    METRICS_PORT = int(os.getenv('METRICS_PORT', 9090))
    
    # Security
    ENABLE_AUTHENTICATION = os.getenv('ENABLE_AUTHENTICATION', 'True').lower() == 'true'
    
    # Rate Limiting
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_STORAGE_URL = REDIS_URL

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Development-specific settings
    SQLALCHEMY_ECHO = True
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Production-specific settings
    SQLALCHEMY_ECHO = False
    LOG_LEVEL = 'INFO'
    
    # Security headers
    SECURE_HEADERS = {
        'STRICT_TRANSPORT_SECURITY': 'max-age=31536000; includeSubDomains',
        'X_CONTENT_TYPE_OPTIONS': 'nosniff',
        'X_FRAME_OPTIONS': 'SAMEORIGIN',
        'X_XSS_PROTECTION': '1; mode=block',
    }

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # Use in-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF protection for testing
    WTF_CSRF_ENABLED = False
    
    # Mock external services
    SLACK_WEBHOOK_URL = None
    OPENAI_API_KEY = None

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
