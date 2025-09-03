"""
Discovery Manager for automatic service discovery
"""

import json
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import threading
import time

logger = logging.getLogger(__name__)

# Configuration file for discovery settings
DISCOVERY_CONFIG_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'discovery_config.json')

class DiscoveryManager:
    """Manages automatic service discovery settings and scheduling"""
    
    def __init__(self):
        self.config_file = DISCOVERY_CONFIG_FILE
        self.scheduler_thread = None
        self.running = False
        self._ensure_config_dir()
        self._load_settings()
    
    def _ensure_config_dir(self):
        """Ensure the config directory exists"""
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
    
    def _load_settings(self):
        """Load discovery settings from config file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.settings = json.load(f)
            else:
                # Default settings
                self.settings = {
                    'enabled': True,
                    'interval': 60,  # minutes
                    'sources': ['ngrok', 'api_base'],
                    'last_run': None,
                    'last_count': 0,
                    'last_status': 'Not configured',
                    'next_run': None
                }
                self._save_settings()
        except Exception as e:
            logger.error(f"Error loading discovery settings: {e}")
            self.settings = {
                'enabled': False,
                'interval': 60,
                'sources': ['ngrok', 'api_base'],
                'last_run': None,
                'last_count': 0,
                'last_status': 'Error loading settings',
                'next_run': None
            }
    
    def _save_settings(self):
        """Save discovery settings to config file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.settings, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving discovery settings: {e}")
    
    def update_settings(self, enabled: bool, interval: int, sources: List[str]):
        """Update discovery settings"""
        self.settings.update({
            'enabled': enabled,
            'interval': interval,
            'sources': sources
        })
        
        # Calculate next run time if enabled
        if enabled:
            self.settings['next_run'] = (datetime.now(timezone.utc) + timedelta(minutes=interval)).isoformat()
        else:
            self.settings['next_run'] = None
        
        self._save_settings()
        
        # Restart scheduler if needed
        if enabled and not self.running:
            self.start_scheduler()
        elif not enabled and self.running:
            self.stop_scheduler()
    
    def update_stats(self, last_run: datetime, services_found: int, status: str):
        """Update discovery statistics"""
        self.settings.update({
            'last_run': last_run.isoformat(),
            'last_count': services_found,
            'last_status': status
        })
        
        # Calculate next run time if enabled
        if self.settings.get('enabled', False):
            interval = self.settings.get('interval', 60)
            self.settings['next_run'] = (last_run + timedelta(minutes=interval)).isoformat()
        
        self._save_settings()
    
    def get_settings(self) -> Dict:
        """Get current discovery settings"""
        return self.settings.copy()
    
    def start_scheduler(self):
        """Start the automatic discovery scheduler"""
        if self.running:
            return
        
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        logger.info("🔍 Automatic service discovery scheduler started")
    
    def stop_scheduler(self):
        """Stop the automatic discovery scheduler"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        logger.info("🔍 Automatic service discovery scheduler stopped")
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                # Check if discovery is enabled
                if not self.settings.get('enabled', False):
                    time.sleep(60)  # Check every minute
                    continue
                
                # Check if it's time to run discovery
                next_run = self.settings.get('next_run')
                if next_run:
                    next_run_dt = datetime.fromisoformat(next_run)
                    if datetime.now(timezone.utc) >= next_run_dt:
                        self._run_discovery()
                
                # Sleep for a minute before checking again
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in discovery scheduler: {e}")
                time.sleep(60)  # Continue after error
    
    def _run_discovery(self):
        """Run the automatic discovery process"""
        try:
            logger.info("🔍 Running automatic service discovery...")
            
            # Create Flask app context for database operations
            from app import create_app
            app = create_app()
            
            with app.app_context():
                # Import here to avoid circular imports
                from app.utils.crawler import crawl_and_update, crawl_api_base_url
                
                services_found = 0
                sources = self.settings.get('sources', ['ngrok', 'api_base'])
                
                # Discover from ngrok tunnel
                if 'ngrok' in sources:
                    try:
                        result = crawl_and_update()
                        if result and isinstance(result, dict):
                            services_found += result.get('services_found', 0)
                    except Exception as e:
                        logger.error(f"Error discovering from ngrok: {e}")
                
                # Discover from API base URL
                if 'api_base' in sources:
                    try:
                        result = crawl_api_base_url()
                        if result and isinstance(result, dict):
                            services_found += result.get('services_found', 0)
                    except Exception as e:
                        logger.error(f"Error discovering from API base: {e}")
                
                # Update statistics
                self.update_stats(
                    last_run=datetime.now(timezone.utc),
                    services_found=services_found,
                    status='success'
                )
                
                # Send notification if services were found
                if services_found > 0:
                    try:
                        from app.utils.slack_notifier import slack_notifier
                        slack_notifier.send_service_discovery_notification(
                            services_found=services_found,
                            sources=sources
                        )
                    except Exception as e:
                        logger.warning(f"Failed to send discovery notification: {e}")
                
                logger.info(f"🔍 Automatic discovery completed. Found {services_found} new services.")
            
        except Exception as e:
            logger.error(f"Error in automatic discovery: {e}")
            self.update_stats(
                last_run=datetime.now(timezone.utc),
                services_found=0,
                status=f'Error: {str(e)}'
            )

# Global discovery manager instance
discovery_manager = DiscoveryManager()

def update_discovery_settings(enabled: bool, interval: int, sources: List[str]):
    """Update discovery settings"""
    discovery_manager.update_settings(enabled, interval, sources)

def update_discovery_stats(last_run: datetime, services_found: int, status: str):
    """Update discovery statistics"""
    discovery_manager.update_stats(last_run, services_found, status)

def get_discovery_settings() -> Dict:
    """Get current discovery settings"""
    return discovery_manager.get_settings()

def start_discovery_scheduler():
    """Start the discovery scheduler"""
    discovery_manager.start_scheduler()

def stop_discovery_scheduler():
    """Stop the discovery scheduler"""
    discovery_manager.stop_scheduler()

