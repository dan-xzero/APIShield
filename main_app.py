#!/usr/bin/env python3
"""
Comprehensive API Security Scan Framework
Main Application with all integrated features
"""

import os
import sys
import logging
from datetime import datetime, timezone
from app import create_app, db
from app.models import User, Service, Endpoint, Scan, Vulnerability, ScanSchedule
from app.config import Config
from app.utils.slack_notifier import slack_notifier
from app.utils.ai_description_generator import AIDescriptionGenerator
from app.utils.scan_scheduler import ScanScheduler
from app.utils.scanner import SecurityScanner
from app.utils.enhanced_parameter_generator import EnhancedParameterGenerator
from app.utils.realtime_monitor import update_realtime_config
import bcrypt
import threading
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class APISecurityFramework:
    """Main API Security Framework class"""
    
    def __init__(self):
        self.app = create_app()
        self.scanner = SecurityScanner()
        self.scheduler = ScanScheduler()
        self.ai_generator = AIDescriptionGenerator()
        self.param_generator = EnhancedParameterGenerator()
        
    def initialize_system(self):
        """Initialize the entire system"""
        with self.app.app_context():
            logger.info("🚀 Initializing API Security Framework")
            
            # Initialize database
            self.init_database()
            
            # Create admin user
            self.create_admin_user()
            
            # Test Slack integration
            self.test_slack_integration()
            
            # Initialize AI components
            self.init_ai_components()
            
            # Check security tools
            self.check_security_tools()
            
            # Initialize real-time monitoring
            try:
                # Initialize real-time monitoring configuration
                from app.utils.realtime_monitor import update_realtime_config
                
                update_realtime_config(
                    check_interval=30,  # Check every 30 seconds
                    auto_scan_enabled=False,  # Start disabled
                    scan_tools=['zap', 'nuclei', 'sqlmap', 'ssrfmap'],
                    scan_depth='comprehensive',
                    change_threshold=0.1  # 10% change threshold
                )
                
                # Start real-time monitoring in a separate thread to avoid blocking
                def start_monitoring_async():
                    try:
                        time.sleep(5)  # Wait for Flask app to be fully ready
                        from app.utils.realtime_monitor import start_realtime_monitoring
                        start_realtime_monitoring()
                        logger.info("🚀 Real-time API monitoring initialized and started")
                        logger.info("🔒 Auto-scanning DISABLED until baseline is established")
                        logger.info("✅ Auto-scanning will be ENABLED after baseline is established")
                    except Exception as e:
                        logger.error(f"❌ Real-time monitoring initialization failed: {e}")
                
                monitoring_thread = threading.Thread(target=start_monitoring_async, daemon=True)
                monitoring_thread.start()
                
            except Exception as e:
                logger.error(f"❌ Real-time monitoring initialization failed: {e}")
            
            logger.info("✅ System initialization complete")
    
    def init_database(self):
        """Initialize database tables"""
        try:
            db.create_all()
            logger.info("✅ Database tables created successfully")
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
            raise
    
    def create_admin_user(self):
        """Create admin user if it doesn't exist"""
        try:
            admin_user = User.query.filter_by(username=Config.ADMIN_USERNAME).first()
            
            if not admin_user:
                # Hash the password
                password_hash = bcrypt.hashpw(
                    Config.ADMIN_PASSWORD.encode('utf-8'), 
                    bcrypt.gensalt()
                ).decode('utf-8')
                
                # Create admin user
                admin_user = User(
                    username=Config.ADMIN_USERNAME,
                    password_hash=password_hash,
                    email='admin@example.com',
                    role='admin',
                    is_active=True
                )
                
                db.session.add(admin_user)
                db.session.commit()
                logger.info(f"✅ Created admin user: {Config.ADMIN_USERNAME}")
            else:
                logger.info(f"ℹ️  Admin user already exists: {Config.ADMIN_USERNAME}")
                
        except Exception as e:
            logger.error(f"❌ Admin user creation failed: {e}")
            raise
    
    def test_slack_integration(self):
        """Test Slack notification integration"""
        try:
            if slack_notifier.enabled:
                success = slack_notifier.test_connection()
                if success:
                    logger.info("✅ Slack integration working")
                    # Send system startup notification
                    slack_notifier.send_system_error(
                        "System Startup",
                        "API Security Framework started successfully",
                        {'timestamp': datetime.now(timezone.utc).isoformat()}
                    )
                else:
                    logger.warning("⚠️  Slack integration test failed")
            else:
                logger.info("ℹ️  Slack notifications disabled")
                
        except Exception as e:
            logger.error(f"❌ Slack integration test failed: {e}")
    
    def init_ai_components(self):
        """Initialize AI components"""
        try:
            # Test AI description generator
            test_data = {
                'method': 'GET',
                'path': '/api/test',
                'summary': 'Test endpoint',
                'description': 'A test endpoint for validation',
                'parameters': []
            }
            
            # Test AI generation (this will cache the test result)
            self.ai_generator.generate_endpoint_description(test_data)
            logger.info("✅ AI description generator initialized")
            
            # Start discovery scheduler
            from app.utils.discovery_manager import start_discovery_scheduler
            start_discovery_scheduler()
            logger.info("✅ Service discovery scheduler started")
            
        except Exception as e:
            logger.error(f"❌ AI components initialization failed: {e}")
            # Don't raise here as AI is optional
    
    def check_security_tools(self):
        """Check if all security tools are available"""
        try:
            tools_status = {
                'ZAP': self.scanner._check_zap_availability(),
                'Nuclei': self.scanner._check_nuclei_availability(),
                'SQLMap': self.scanner._check_sqlmap_availability(),
                'SSRFMap': self.scanner._check_ssrfmap_availability(),
                'XSStrike': self.scanner._check_xsstrike_availability()
            }
            
            available_tools = [tool for tool, available in tools_status.items() if available]
            unavailable_tools = [tool for tool, available in tools_status.items() if not available]
            
            if available_tools:
                logger.info(f"✅ Available security tools: {', '.join(available_tools)}")
            
            if unavailable_tools:
                logger.warning(f"⚠️  Unavailable security tools: {', '.join(unavailable_tools)}")
                
        except Exception as e:
            logger.error(f"❌ Security tools check failed: {e}")
    
    def run_scheduled_scans(self):
        """Run all scheduled scans"""
        try:
            with self.app.app_context():
                results = self.scheduler.run_due_scans()
                if results:
                    logger.info(f"✅ Ran {len(results)} scheduled scans")
                    for result in results:
                        if result['success']:
                            logger.info(f"   ✅ {result['schedule_name']}: {result['scans_run']} scans, {result['vulnerabilities_found']} vulnerabilities")
                        else:
                            logger.error(f"   ❌ {result['schedule_name']}: {result.get('error', 'Unknown error')}")
                else:
                    logger.info("ℹ️  No scheduled scans due")
                    
        except Exception as e:
            logger.error(f"❌ Scheduled scans execution failed: {e}")
    
    def generate_daily_summary(self):
        """Generate and send daily summary"""
        try:
            with self.app.app_context():
                from datetime import datetime, timedelta
                
                today = datetime.now(timezone.utc).date()
                start_of_day = datetime.combine(today, datetime.min.time())
                end_of_day = datetime.combine(today, datetime.max.time())
                
                # Get today's statistics
                total_vulns = Vulnerability.query.filter(
                    Vulnerability.created_at >= start_of_day,
                    Vulnerability.created_at <= end_of_day
                ).count()
                
                high_risk = Vulnerability.query.filter(
                    Vulnerability.created_at >= start_of_day,
                    Vulnerability.created_at <= end_of_day,
                    Vulnerability.severity.in_(['high', 'critical'])
                ).count()
                
                scans_run = Scan.query.filter(
                    Scan.created_at >= start_of_day,
                    Scan.created_at <= end_of_day
                ).count()
                
                services_scanned = Service.query.count()
                endpoints_scanned = Endpoint.query.count()
                
                summary_data = {
                    'total_vulnerabilities': total_vulns,
                    'high_risk': high_risk,
                    'scans_run': scans_run,
                    'services_scanned': services_scanned,
                    'endpoints_scanned': endpoints_scanned,
                    'date': today.isoformat()
                }
                
                if slack_notifier.enabled:
                    success = slack_notifier.send_daily_summary(summary_data)
                    if success:
                        logger.info("✅ Daily summary sent to Slack")
                    else:
                        logger.warning("⚠️  Failed to send daily summary")
                
                logger.info(f"📊 Daily Summary: {total_vulns} vulnerabilities, {scans_run} scans, {high_risk} high-risk")
                
        except Exception as e:
            logger.error(f"❌ Daily summary generation failed: {e}")
    
    def run_comprehensive_scan(self, service_name=None):
        """Run a comprehensive security scan"""
        try:
            with self.app.app_context():
                if service_name:
                    services = Service.query.filter(Service.name.ilike(f'%{service_name}%')).all()
                else:
                    services = Service.query.all()
                
                if not services:
                    logger.warning("⚠️  No services found for scanning")
                    return
                
                total_vulnerabilities = 0
                total_scans = 0
                
                for service in services:
                    logger.info(f"🔍 Scanning service: {service.name}")
                    
                    endpoints = Endpoint.query.filter_by(service_id=service.id).all()
                    if not endpoints:
                        logger.warning(f"   ⚠️  No endpoints found for {service.name}")
                        continue
                    
                    service_vulns = 0
                    service_scans = 0
                    
                    for endpoint in endpoints:
                        try:
                            # Generate parameters
                            result = self.param_generator.generate_and_validate_parameters(endpoint, use_ai=True)
                            
                            if result['validation']['success']:
                                # Run scan
                                scan_result = self.scanner.scan_endpoint(
                                    endpoint.__dict__, 
                                    result['parameters'], 
                                    'combined'
                                )
                                
                                service_scans += 1
                                total_scans += 1
                                
                                vulnerabilities = scan_result.get('vulnerabilities', [])
                                service_vulns += len(vulnerabilities)
                                total_vulnerabilities += len(vulnerabilities)
                                
                                logger.info(f"   ✅ {endpoint.path}: {len(vulnerabilities)} vulnerabilities")
                            else:
                                logger.warning(f"   ⚠️  Skipped {endpoint.path}: parameter validation failed")
                                
                        except Exception as e:
                            logger.error(f"   ❌ Error scanning {endpoint.path}: {e}")
                            continue
                    
                    logger.info(f"   📊 {service.name}: {service_scans} scans, {service_vulns} vulnerabilities")
                
                logger.info(f"🎯 Comprehensive scan complete: {total_scans} scans, {total_vulnerabilities} vulnerabilities")
                
                # Send summary notification
                if slack_notifier.enabled:
                    slack_notifier.send_scan_completed(
                        "Comprehensive Scan",
                        total_vulnerabilities,
                        0,  # Duration not tracked in this method
                        "combined"
                    )
                
        except Exception as e:
            logger.error(f"❌ Comprehensive scan failed: {e}")
    
    def get_system_status(self):
        """Get comprehensive system status"""
        try:
            with self.app.app_context():
                status = {
                    'database': {
                        'services': Service.query.count(),
                        'endpoints': Endpoint.query.count(),
                        'scans': Scan.query.count(),
                        'vulnerabilities': Vulnerability.query.count(),
                        'schedules': ScanSchedule.query.count()
                    },
                    'slack': {
                        'enabled': slack_notifier.enabled,
                        'connected': slack_notifier.test_connection() if slack_notifier.enabled else False
                    },
                    'security_tools': {
                        'ZAP': self.scanner._check_zap_availability(),
                        'Nuclei': self.scanner._check_nuclei_availability(),
                        'SQLMap': self.scanner._check_sqlmap_availability(),
                        'SSRFMap': self.scanner._check_ssrfmap_availability(),
                        'XSStrike': self.scanner._check_xsstrike_availability()
                    },
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                return status
                
        except Exception as e:
            logger.error(f"❌ System status check failed: {e}")
            return None

def main():
    """Main application entry point"""
    try:
        # Create framework instance
        framework = APISecurityFramework()
        
        # Initialize system
        framework.initialize_system()
        
        # Get system status
        status = framework.get_system_status()
        if status:
            logger.info("📊 System Status:")
            logger.info(f"   Database: {status['database']['services']} services, {status['database']['endpoints']} endpoints")
            logger.info(f"   Scans: {status['database']['scans']} total, {status['database']['vulnerabilities']} vulnerabilities")
            logger.info(f"   Schedules: {status['database']['schedules']} active")
            logger.info(f"   Slack: {'Connected' if status['slack']['connected'] else 'Not connected'}")
            
            available_tools = [tool for tool, available in status['security_tools'].items() if available]
            logger.info(f"   Security Tools: {', '.join(available_tools)}")
        
        # Run the Flask application
        debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
        host = os.getenv('FLASK_HOST', '0.0.0.0')
        port = int(os.getenv('FLASK_PORT', 5001))
        
        logger.info(f"🚀 Starting API Security Framework on {host}:{port}")
        logger.info(f"   Debug mode: {debug}")
        logger.info(f"   Target portal: {Config.API_PORTAL_URL}")
        logger.info(f"   API base: {Config.API_BASE_URL}")
        
        framework.app.run(
            host=host,
            port=port,
            debug=debug
        )
        
    except Exception as e:
        logger.error(f"❌ Application startup failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
