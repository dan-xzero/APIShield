"""
API Security Scan Framework - Main Application
"""

import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

def create_app(config_name=None):
    """Application factory pattern"""
    import os
    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
    app = Flask(__name__, template_folder=template_dir)
    
    # Load configuration
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    app.config.from_object(f'app.config.{config_name.capitalize()}Config')
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    
    # Configure login manager
    login_manager.login_view = 'dashboard.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    # Setup logging
    setup_logging(app)
    
    # Register blueprints
    from app.routes.dashboard import dashboard_bp
    from app.routes.api import api_bp
    
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Import auth module to register user_loader (must be after login_manager.init_app)
    from app.auth import load_user
    login_manager.user_loader(load_user)
    
    # Register custom template filters
    from croniter import croniter
    
    @app.template_filter('cron_description')
    def cron_description_filter(cron_expression):
        """Convert cron expression to human-readable description"""
        try:
            cron = croniter(cron_expression)
            # Get next few occurrences to understand the pattern
            next_runs = [cron.get_next() for _ in range(3)]
            
            # Simple pattern detection
            if cron_expression == '0 0 * * *':
                return 'Daily at midnight'
            elif cron_expression == '0 */6 * * *':
                return 'Every 6 hours'
            elif cron_expression == '0 */12 * * *':
                return 'Every 12 hours'
            elif cron_expression == '0 9 * * 1-5':
                return 'Weekdays at 9 AM'
            elif cron_expression == '0 0 * * 0':
                return 'Weekly on Sunday'
            elif cron_expression == '0 0 1 * *':
                return 'Monthly on the 1st'
            else:
                return f'Custom schedule ({cron_expression})'
        except Exception:
            return f'Invalid cron expression ({cron_expression})'
    
    @app.template_filter('format_interval')
    def format_interval_filter(minutes):
        """Convert minutes to human-readable interval format"""
        if minutes is None:
            return 'Not set'
        
        minutes = int(minutes)
        
        if minutes >= 1440:  # 24 hours
            days = minutes // 1440
            return f'{days} day{"s" if days != 1 else ""}'
        elif minutes >= 60:  # 1 hour
            hours = minutes // 60
            return f'{hours} hour{"s" if hours != 1 else ""}'
        else:
            return f'{minutes} minute{"s" if minutes != 1 else ""}'
    
    @app.template_filter('format_seconds')
    def format_seconds_filter(seconds):
        """Convert seconds to human-readable format"""
        if seconds is None:
            return 'Not set'
        
        seconds = int(seconds)
        
        if seconds >= 86400:  # 24 hours
            days = seconds // 86400
            return f'{days} day{"s" if days != 1 else ""}'
        elif seconds >= 3600:  # 1 hour
            hours = seconds // 3600
            return f'{hours} hour{"s" if hours != 1 else ""}'
        elif seconds >= 60:  # 1 minute
            minutes = seconds // 60
            return f'{minutes} minute{"s" if minutes != 1 else ""}'
        else:
            return f'{seconds} second{"s" if seconds != 1 else ""}'
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app

def setup_logging(app):
    """Configure application logging"""
    log_level = os.getenv('LOG_LEVEL', 'INFO')
    log_file = os.getenv('LOG_FILE', 'logs/api_scanner.log')
    
    # Create logs directory if it doesn't exist
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    # Set Flask logger level
    app.logger.setLevel(getattr(logging, log_level.upper()))

# Import models to ensure they are registered with SQLAlchemy
from app.models import Service, ApiVersion, Endpoint, Scan, Vulnerability, ScanTarget


