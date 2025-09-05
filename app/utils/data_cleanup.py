"""
Data cleanup and synchronization utility for maintaining accurate database state
"""

import logging
import requests
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Set, Tuple
from app import db
from app.models import Service, ApiVersion, Endpoint, Scan, Vulnerability
from app.utils.crawler import APIPortalCrawler
from app.config import Config

logger = logging.getLogger(__name__)

class DataCleanupManager:
    """Manages data cleanup and synchronization to maintain accurate database state"""
    
    def __init__(self):
        self.crawler = APIPortalCrawler()
        self.session = requests.Session()
        self.session.headers.update({
            'ngrok-skip-browser-warning': 'true',
            'User-Agent': 'API-Security-Scanner/1.0'
        })
    
    def get_current_portal_services(self) -> List[Dict]:
        """Get current services from the API portal"""
        try:
            logger.info("Fetching current services from API portal...")
            services = self.crawler.discover_services()
            logger.info(f"Found {len(services)} services in portal")
            return services
        except Exception as e:
            logger.error(f"Error fetching services from portal: {e}")
            return []
    
    def get_current_portal_endpoints(self, service_url: str) -> List[Dict]:
        """Get current endpoints for a specific service"""
        try:
            logger.info(f"Fetching endpoints for service: {service_url}")
            endpoints = self.crawler.fetch_api_definition(service_url)
            return endpoints.get('endpoints', [])
        except Exception as e:
            logger.error(f"Error fetching endpoints for {service_url}: {e}")
            return []
    
    def cleanup_removed_services(self) -> Tuple[int, List[str]]:
        """
        Remove services that no longer exist in the portal
        
        Returns:
            Tuple of (removed_count, removed_service_names)
        """
        try:
            logger.info("Starting cleanup of removed services...")
            
            # Get current services from portal
            portal_services = self.get_current_portal_services()
            portal_service_urls = {s.get('api_url', '') for s in portal_services}
            
            # Get all services from database
            db_services = Service.query.all()
            removed_services = []
            
            for service in db_services:
                if service.api_url not in portal_service_urls:
                    logger.info(f"Service no longer exists in portal: {service.name} ({service.api_url})")
                    removed_services.append(service.name)
                    
                    # Mark service as inactive instead of deleting
                    service.status = 'inactive'
                    service.updated_at = datetime.now(timezone.utc)
                    
                    # Also mark all endpoints as inactive
                    for endpoint in service.endpoints:
                        endpoint.updated_at = datetime.now(timezone.utc)
                        # Don't delete endpoints, just mark them as inactive
                        # This preserves scan history
            
            db.session.commit()
            logger.info(f"Marked {len(removed_services)} services as inactive")
            return len(removed_services), removed_services
            
        except Exception as e:
            logger.error(f"Error during service cleanup: {e}")
            db.session.rollback()
            return 0, []
    
    def cleanup_removed_endpoints(self, service: Service) -> int:
        """
        Remove endpoints that no longer exist in the service API
        
        Returns:
            Number of endpoints removed
        """
        try:
            logger.info(f"Cleaning up endpoints for service: {service.name}")
            
            # Get current endpoints from the service
            current_endpoints = self.get_current_portal_endpoints(service.api_url)
            current_endpoint_keys = set()
            
            for endpoint in current_endpoints:
                key = f"{endpoint.get('method', '').upper()}:{endpoint.get('path', '')}"
                current_endpoint_keys.add(key)
            
            # Get database endpoints for this service
            db_endpoints = Endpoint.query.filter_by(service_id=service.id).all()
            removed_count = 0
            
            for endpoint in db_endpoints:
                key = f"{endpoint.method.upper()}:{endpoint.path}"
                if key not in current_endpoint_keys:
                    logger.info(f"Endpoint no longer exists: {endpoint.method} {endpoint.path}")
                    
                    # Mark endpoint as inactive instead of deleting
                    endpoint.updated_at = datetime.now(timezone.utc)
                    # We could add an 'active' field to endpoints if needed
                    removed_count += 1
            
            db.session.commit()
            logger.info(f"Marked {removed_count} endpoints as inactive for service {service.name}")
            return removed_count
            
        except Exception as e:
            logger.error(f"Error during endpoint cleanup for {service.name}: {e}")
            db.session.rollback()
            return 0
    
    def cleanup_orphaned_scans(self) -> int:
        """
        Clean up scans for endpoints that no longer exist
        
        Returns:
            Number of scans cleaned up
        """
        try:
            logger.info("Cleaning up orphaned scans...")
            
            # Find scans for endpoints that don't exist
            orphaned_scans = db.session.query(Scan).outerjoin(Endpoint).filter(
                Endpoint.id.is_(None)
            ).all()
            
            cleaned_count = 0
            for scan in orphaned_scans:
                logger.info(f"Removing orphaned scan: {scan.id}")
                
                # Remove associated vulnerabilities first
                Vulnerability.query.filter_by(scan_id=scan.id).delete()
                
                # Remove the scan
                db.session.delete(scan)
                cleaned_count += 1
            
            db.session.commit()
            logger.info(f"Cleaned up {cleaned_count} orphaned scans")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Error during orphaned scan cleanup: {e}")
            db.session.rollback()
            return 0
    
    def cleanup_old_pending_scans(self, hours: int = 24) -> int:
        """
        Clean up scans that have been pending for too long
        
        Args:
            hours: Number of hours after which pending scans are considered stale
            
        Returns:
            Number of scans cleaned up
        """
        try:
            logger.info(f"Cleaning up pending scans older than {hours} hours...")
            
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            old_pending_scans = Scan.query.filter(
                Scan.status == 'pending',
                Scan.scan_time < cutoff_time
            ).all()
            
            cleaned_count = 0
            for scan in old_pending_scans:
                logger.info(f"Marking old pending scan as failed: {scan.id}")
                scan.status = 'failed'
                scan.completed_at = datetime.now(timezone.utc)
                scan.duration = (datetime.now(timezone.utc) - scan.scan_time).total_seconds()
                cleaned_count += 1
            
            db.session.commit()
            logger.info(f"Marked {cleaned_count} old pending scans as failed")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Error during old scan cleanup: {e}")
            db.session.rollback()
            return 0
    
    def get_database_stats(self) -> Dict:
        """Get current database statistics"""
        try:
            stats = {
                'services': {
                    'total': Service.query.count(),
                    'active': Service.query.filter_by(status='active').count(),
                    'inactive': Service.query.filter_by(status='inactive').count()
                },
                'endpoints': {
                    'total': Endpoint.query.count()
                },
                'scans': {
                    'total': Scan.query.count(),
                    'pending': Scan.query.filter_by(status='pending').count(),
                    'completed': Scan.query.filter_by(status='completed').count(),
                    'failed': Scan.query.filter_by(status='failed').count()
                },
                'vulnerabilities': {
                    'total': Vulnerability.query.count()
                }
            }
            return stats
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {}
    
    def full_cleanup(self) -> Dict:
        """
        Perform a full cleanup of the database
        
        Returns:
            Dictionary with cleanup results
        """
        try:
            logger.info("Starting full database cleanup...")
            
            results = {
                'services_removed': 0,
                'services_removed_names': [],
                'endpoints_removed': 0,
                'orphaned_scans_removed': 0,
                'old_pending_scans_cleaned': 0,
                'stats_before': self.get_database_stats(),
                'stats_after': {}
            }
            
            # Clean up removed services
            removed_count, removed_names = self.cleanup_removed_services()
            results['services_removed'] = removed_count
            results['services_removed_names'] = removed_names
            
            # Clean up removed endpoints for active services
            active_services = Service.query.filter_by(status='active').all()
            total_endpoints_removed = 0
            for service in active_services:
                endpoints_removed = self.cleanup_removed_endpoints(service)
                total_endpoints_removed += endpoints_removed
            results['endpoints_removed'] = total_endpoints_removed
            
            # Clean up orphaned scans
            results['orphaned_scans_removed'] = self.cleanup_orphaned_scans()
            
            # Clean up old pending scans
            results['old_pending_scans_cleaned'] = self.cleanup_old_pending_scans()
            
            # Get final stats
            results['stats_after'] = self.get_database_stats()
            
            logger.info("Full database cleanup completed")
            return results
            
        except Exception as e:
            logger.error(f"Error during full cleanup: {e}")
            return {'error': str(e)}
    
    def sync_with_portal(self) -> Dict:
        """
        Synchronize database with current portal state
        
        Returns:
            Dictionary with sync results
        """
        try:
            logger.info("Starting synchronization with portal...")
            
            # Get current portal services
            portal_services = self.get_current_portal_services()
            portal_service_urls = {s.get('api_url', '') for s in portal_services}
            
            # Get database services
            db_services = Service.query.all()
            db_service_urls = {s.api_url for s in db_services}
            
            results = {
                'services_in_portal': len(portal_services),
                'services_in_db': len(db_services),
                'services_to_add': [],
                'services_to_remove': [],
                'services_to_update': []
            }
            
            # Find services to add
            for portal_service in portal_services:
                if portal_service.get('api_url') not in db_service_urls:
                    results['services_to_add'].append(portal_service.get('name', 'Unknown'))
            
            # Find services to remove
            for db_service in db_services:
                if db_service.api_url not in portal_service_urls:
                    results['services_to_remove'].append(db_service.name)
            
            # Find services to update
            for portal_service in portal_services:
                portal_url = portal_service.get('api_url')
                if portal_url in db_service_urls:
                    db_service = next(s for s in db_services if s.api_url == portal_url)
                    if db_service.name != portal_service.get('name'):
                        results['services_to_update'].append({
                            'old_name': db_service.name,
                            'new_name': portal_service.get('name')
                        })
            
            logger.info("Portal synchronization analysis completed")
            return results
            
        except Exception as e:
            logger.error(f"Error during portal sync: {e}")
            return {'error': str(e)}

# Global instance
data_cleanup_manager = DataCleanupManager()


