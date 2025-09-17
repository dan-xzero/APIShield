"""
Real-Time API Change Detection & Auto-Scanning System
"""

import json
import os
import logging
import hashlib
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
import sqlite3

logger = logging.getLogger(__name__)

@dataclass
class APISnapshot:
    """Snapshot of API state at a point in time"""
    timestamp: datetime
    service_id: str
    endpoint_count: int
    endpoints_hash: str
    services_hash: str
    changes_detected: bool = False
    scan_triggered: bool = False
    endpoints: List[Dict] = None  # Store endpoint details for granular change detection
    change_details: List[Dict] = None  # Store actual change details for display

class RealTimeMonitor:
    """Real-time monitoring system for API changes and automatic scanning"""
    
    def __init__(self, db_path: str = None):
        # Always use absolute path to avoid working directory issues
        if db_path is None:
            # Use absolute path to the instance directory
            self.db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'instance', 'api_scanner.db')
        else:
            self.db_path = db_path
        self.running = False
        self.monitor_thread = None
        self.check_interval = 30  # Check every 30 seconds
        self.last_check = None
        self.snapshots: Dict[str, APISnapshot] = {}
        self.change_threshold = 0.1  # 10% change threshold
        self.auto_scan_enabled = True
        self.scan_tools = ['zap', 'nuclei', 'sqlmap', 'ssrfmap']  # All tools by default
        self.scan_depth = 'comprehensive'  # Comprehensive scanning for changes
        
        # Load configuration
        self.config_file = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'realtime_config.json')
        self._load_config()
        
        logger.info(f"🔍 Real-time API monitoring system initialized with database: {self.db_path}")
        logger.info(f"🔍 Database file exists: {os.path.exists(self.db_path)}")
    
    def _load_config(self):
        """Load real-time monitoring configuration"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.check_interval = config.get('check_interval', 30)
                    self.auto_scan_enabled = config.get('auto_scan_enabled', True)
                    self.scan_tools = config.get('scan_tools', ['zap', 'nuclei', 'sqlmap', 'ssrfmap'])
                    self.scan_depth = config.get('scan_depth', 'comprehensive')
                    self.change_threshold = config.get('change_threshold', 0.1)
            else:
                self._save_config()
        except Exception as e:
            logger.error(f"Error loading real-time config: {e}")
            self._save_config()
    
    def _save_config(self):
        """Save real-time monitoring configuration"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            config = {
                'check_interval': self.check_interval,
                'auto_scan_enabled': self.auto_scan_enabled,
                'scan_tools': self.scan_tools,
                'scan_depth': self.scan_depth,
                'change_threshold': self.change_threshold,
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving real-time config: {e}")
    
    def update_config(self, **kwargs):
        """Update real-time monitoring configuration"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        self._save_config()
        logger.info(f"🔧 Real-time monitoring configuration updated: {kwargs}")
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.running:
            logger.info("🔍 Real-time monitoring is already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("🚀 Real-time API monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("🛑 Real-time API monitoring stopped")
    
    def establish_baseline(self):
        """Manually establish baseline snapshot without scanning"""
        try:
            logger.info("📊 Manually establishing baseline snapshot...")
            
            # Clear existing snapshots
            self.snapshots.clear()
            
            # Get current API state
            current_state = self._get_current_api_state()
            
            if current_state:
                # Update snapshots to create baseline
                self._update_snapshots(current_state)
                logger.info(f"✅ Baseline manually established for {len(current_state)} services")
                logger.info("🔒 No scanning will occur until changes are detected")
                return True
            else:
                logger.warning("⚠️ No services found for baseline creation")
                return False
                
        except Exception as e:
            logger.error(f"Error establishing baseline: {e}")
            return False
    
    def reset_baseline(self):
        """Reset baseline and force re-establishment"""
        try:
            logger.info("🔄 Resetting baseline snapshot...")
            self.snapshots.clear()
            logger.info("✅ Baseline reset - next check will establish new baseline")
            return True
        except Exception as e:
            logger.error(f"Error resetting baseline: {e}")
            return False
    
    def enable_auto_scanning(self):
        """Enable auto-scanning after baseline is established"""
        try:
            if not self.snapshots:
                logger.warning("⚠️ Cannot enable auto-scanning: No baseline established")
                return False
            
            self.auto_scan_enabled = True
            self._save_config()
            logger.info("✅ Auto-scanning enabled - system will now scan changed endpoints")
            return True
            
        except Exception as e:
            logger.error(f"Error enabling auto-scanning: {e}")
            return False
    
    def disable_auto_scanning(self):
        """Disable auto-scanning"""
        try:
            self.auto_scan_enabled = False
            self._save_config()
            logger.info("🔒 Auto-scanning disabled - no scans will be triggered")
            return True
            
        except Exception as e:
            logger.error(f"Error disabling auto-scanning: {e}")
            return False
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Check if it's time to run monitoring
                if (not self.last_check or 
                    (current_time - self.last_check).total_seconds() >= self.check_interval):
                    
                    self._check_for_changes()
                    self.last_check = current_time
                
                # Sleep for a short interval
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in real-time monitoring loop: {e}")
                time.sleep(10)  # Continue after error
    
    def _check_for_changes(self):
        """Check for API changes and trigger scans if needed with baseline-first approach"""
        try:
            # Check if baseline has been established
            if not self.snapshots:
                # First run: Create baseline without scanning
                logger.info("📊 First run detected - creating baseline snapshot...")
                logger.info("🔒 Baseline mode: No scanning will occur until changes are detected")
                
                current_state = self._get_current_api_state()
                if current_state:
                    # Update snapshots to create baseline
                    self._update_snapshots(current_state)
                    logger.info(f"✅ Baseline established for {len(current_state)} services")
                    
                    # Enable auto-scanning after baseline is established
                    self.auto_scan_enabled = True  # ENABLED - auto-scanning active
                    self._save_config()
                    logger.info("✅ Auto-scanning ENABLED - ready to detect and scan changes")
                else:
                    logger.warning("⚠️ No services found for baseline creation")
                return
            
            # Subsequent runs: Detect changes and scan
            logger.debug("🔍 Checking for changes against baseline...")
            
            # Get current API state
            current_state = self._get_current_api_state()
            
            # Compare with previous snapshots
            changes_detected = self._detect_changes(current_state)
            
            if changes_detected:
                logger.info(f"🚨 Detected {len(changes_detected)} API changes:")
                for change in changes_detected:
                    logger.info(f"   - {change['change_type']}: {change['details']}")
                    if 'affected_endpoints' in change:
                        ep_count = len(change['affected_endpoints'])
                        logger.info(f"     Affected endpoints: {ep_count}")
                
                logger.info("🚀 Triggering automatic scans for changed endpoints...")
                self._trigger_auto_scans(changes_detected)
            else:
                logger.info("✅ No API changes detected")
            
            # Update snapshots
            self._update_snapshots(current_state, changes_detected)
            
        except Exception as e:
            logger.error(f"Error checking for API changes: {e}")
    
    def _get_current_api_state(self) -> Dict:
        """Get current state of all APIs with individual endpoint tracking"""
        try:
            # Use existing Flask app context instead of creating new one
            from flask import current_app
            from app.models import Service, Endpoint
            
            # Try to use Flask app context, fallback to direct database connection
            try:
                # Import database from app
                from app import db
                
                # Get services with detailed endpoint information
                services = db.session.query(
                    Service.id,
                    Service.name,
                    Service.api_url,
                    Service.created_at,
                    db.func.count(Endpoint.id).label('endpoint_count')
                ).outerjoin(Endpoint).group_by(Service.id).all()
                
                # Convert to list of dictionaries
                services_list = [
                    {
                        'id': service.id,
                        'name': service.name, 
                        'api_url': service.api_url,
                        'created_at': service.created_at,
                        'endpoint_count': service.endpoint_count
                    }
                    for service in services
                ]
                
                logger.info(f"Flask app context: Found {len(services_list)} services")
                
                # Commit the transaction to ensure data is available
                db.session.commit()
                
                # Use the services_list from Flask app context
                services = services_list
                
            except Exception as e:
                # Fallback to direct database connection if no app context
                logger.warning(f"No Flask app context, using direct database connection: {e}")
                import sqlite3
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get services count
                cursor.execute("SELECT COUNT(*) FROM services")
                service_count = cursor.fetchone()[0]
                
                # Get endpoints count
                cursor.execute("SELECT COUNT(*) FROM endpoints")
                endpoint_count = cursor.fetchone()[0]
                
                conn.close()
                
                logger.info(f"Direct DB connection: {service_count} services, {endpoint_count} endpoints")
                
                if service_count == 0:
                    return {}
                
                # Use direct SQL for service data
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT s.id, s.name, s.api_url, s.created_at, COUNT(e.id) as endpoint_count
                    FROM services s 
                    LEFT OUTER JOIN endpoints e ON s.id = e.service_id 
                    GROUP BY s.id
                """)
                services_data = cursor.fetchall()
                
                # Convert to list of dictionaries
                services = [
                    {
                        'id': row[0],
                        'name': row[1], 
                        'api_url': row[2],
                        'created_at': row[3],
                        'endpoint_count': row[4]
                    }
                    for row in services_data
                ]
                
                conn.close()
                
                # Calculate hashes for change detection
                state = {}
                logger.info(f"Processing {len(services)} services for state creation")
                for service in services:
                    # Get detailed endpoint information for this service
                    try:
                        # Try Flask app context first
                        from app import db
                        
                        endpoints = db.session.query(
                            Endpoint.id,
                            Endpoint.path,
                            Endpoint.method,
                            Endpoint.parameters_schema,
                            Endpoint.request_body_schema,
                            Endpoint.updated_at
                        ).filter_by(service_id=service['id']).all()
                        
                        # Convert to list of dictionaries
                        endpoint_details = []
                        for ep in endpoints:
                            # Create a hash for each endpoint based on its key properties including description
                            ep_hash_data = f"{ep.path}:{ep.method}:{ep.parameters_schema or ''}:{ep.request_body_schema or ''}:{ep.description or ''}"
                            ep_hash = hashlib.md5(ep_hash_data.encode()).hexdigest()
                            
                            endpoint_details.append({
                                'id': ep.id,
                                'path': ep.path,
                                'method': ep.method,
                                'hash': ep_hash,
                                'updated_at': ep.updated_at
                            })
                            
                    except RuntimeError:
                        # Fallback to direct database connection
                        conn = sqlite3.connect(self.db_path)
                        cursor = conn.cursor()
                        
                        cursor.execute("""
                            SELECT id, path, method, parameters_schema, request_body_schema, description, updated_at
                            FROM endpoints 
                            WHERE service_id = ?
                        """, (service['id'],))
                        
                        endpoints = cursor.fetchall()
                        conn.close()
                        
                        # Convert to list of dictionaries
                        endpoint_details = []
                        for ep in endpoints:
                            # Create a hash for each endpoint based on its key properties including description
                            ep_hash_data = f"{ep[1]}:{ep[2]}:{ep[3] or ''}:{ep[4] or ''}:{ep[5] or ''}"
                            ep_hash = hashlib.md5(ep_hash_data.encode()).hexdigest()
                            
                            endpoint_details.append({
                                'id': ep[0],
                                'path': ep[1],
                                'method': ep[2],
                                'hash': ep_hash,
                                'updated_at': ep[6]
                            })
                    
                    # Create service-level hash from all endpoint hashes
                    endpoints_str = ':'.join([f"{ep['path']}:{ep['method']}:{ep['hash']}" for ep in endpoint_details])
                    endpoints_hash = hashlib.md5(endpoints_str.encode()).hexdigest()
                    
                    state[service['id']] = {
                        'service_id': service['id'],
                        'name': service['name'],
                        'api_url': service['api_url'],
                        'created_at': service['created_at'],
                        'endpoint_count': service['endpoint_count'],
                        'endpoints_hash': endpoints_hash,
                        'endpoints': endpoint_details,  # Store individual endpoint details
                        'timestamp': datetime.now(timezone.utc)
                    }
                
                logger.info(f"Successfully created state for {len(state)} services")
                return state
                
        except Exception as e:
            logger.error(f"Error getting current API state: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {}
    
    def _detect_changes(self, current_state: Dict) -> List[Dict]:
        """Detect changes between current and previous API state with endpoint-level granularity"""
        changes = []
        
        for service_id, current_service in current_state.items():
            previous_snapshot = self.snapshots.get(service_id)
            
            if not previous_snapshot:
                # New service discovered
                changes.append({
                    'service_id': service_id,
                    'change_type': 'new_service',
                    'details': f"New service discovered: {current_service['name']}",
                    'severity': 'high',
                    'affected_endpoints': current_service['endpoints']  # All endpoints in new service
                })
                continue
            
            # Initialize variables for endpoint changes
            changed_endpoints = []
            new_endpoints = []
            removed_endpoints = []
            
            # Check for endpoint-level changes
            if current_service['endpoints_hash'] != previous_snapshot.endpoints_hash:
                # Get previous endpoint details from snapshot
                previous_endpoints = getattr(previous_snapshot, 'endpoints', [])
                current_endpoints = current_service['endpoints']
                
                # Create lookup dictionaries for efficient comparison
                current_ep_lookup = {ep['path'] + ':' + ep['method']: ep for ep in current_endpoints}
                previous_ep_lookup = {ep['path'] + ':' + ep['method']: ep for ep in previous_endpoints}
                
                # Find new and changed endpoints
                for ep_key, current_ep in current_ep_lookup.items():
                    if ep_key not in previous_ep_lookup:
                        new_endpoints.append(current_ep)
                    elif current_ep['hash'] != previous_ep_lookup[ep_key]['hash']:
                        changed_endpoints.append(current_ep)
                
                # Find removed endpoints
                for ep_key, previous_ep in previous_ep_lookup.items():
                    if ep_key not in current_ep_lookup:
                        removed_endpoints.append(previous_ep)
                
                # Create change records for different types of changes
                if new_endpoints:
                    changes.append({
                        'service_id': service_id,
                        'change_type': 'new_endpoints',
                        'details': f"New endpoints detected: {len(new_endpoints)} endpoints added",
                        'severity': 'medium',
                        'affected_endpoints': new_endpoints
                    })
                
                if changed_endpoints:
                    changes.append({
                        'service_id': service_id,
                        'change_type': 'modified_endpoints',
                        'details': f"Modified endpoints detected: {len(changed_endpoints)} endpoints changed",
                        'severity': 'medium',
                        'affected_endpoints': changed_endpoints
                    })
                
                if removed_endpoints:
                    changes.append({
                        'service_id': service_id,
                        'change_type': 'removed_endpoints',
                        'details': f"Removed endpoints detected: {len(removed_endpoints)} endpoints removed",
                        'severity': 'low',
                        'affected_endpoints': removed_endpoints
                    })
            
            # Check for significant changes (above threshold) - but only if no specific endpoint changes were detected
            if previous_snapshot.endpoint_count > 0 and not changed_endpoints and not new_endpoints and not removed_endpoints:
                change_percentage = abs(current_service['endpoint_count'] - previous_snapshot.endpoint_count) / previous_snapshot.endpoint_count
                
                if change_percentage >= self.change_threshold:
                    # Only scan endpoints that actually changed, not all endpoints
                    # This prevents full service scans when only a few endpoints changed
                    logger.warning(f"Significant change detected ({change_percentage:.1%}) but no specific endpoint changes found - this may indicate a detection issue")
                    # Don't add this change to avoid full service scans
                    # Instead, log it for investigation
        
        return changes
    
    def _trigger_auto_scans(self, changes: List[Dict]):
        """Automatically trigger security scans for changed APIs"""
        if not self.auto_scan_enabled:
            logger.info("🔒 Auto-scanning is disabled, skipping scan triggers")
            return
        
        try:
            # Import here to avoid circular imports
            from app.tasks import scan_endpoint
            from app.models import Service, Endpoint
            from app import create_app, db
            
            app = create_app()
            with app.app_context():
                for change in changes:
                    service_id = change['service_id']
                    
                    # Get service info
                    service = Service.query.get(service_id)
                    if not service:
                        logger.warning(f"Service {service_id} not found for auto-scanning")
                        continue
                    
                    # Get only the affected endpoints for this change
                    affected_endpoints = change.get('affected_endpoints', [])
                    
                    if not affected_endpoints:
                        logger.warning(f"No affected endpoints found for change: {change['change_type']}")
                        continue
                    
                    logger.info(f"🚀 Triggering auto-scan for {len(affected_endpoints)} affected endpoints in service: {service.name}")
                    logger.info(f"   Change type: {change['change_type']}")
                    logger.info(f"   Affected endpoints: {[ep['path'] for ep in affected_endpoints]}")
                    
                    # Trigger scans only for the affected endpoints
                    for endpoint_info in affected_endpoints:
                        try:
                            # Debug logging for endpoint info
                            logger.info(f"🔍 Processing endpoint info: {endpoint_info}")
                            
                            # Validate endpoint info structure
                            if not isinstance(endpoint_info, dict) or 'id' not in endpoint_info:
                                logger.warning(f"Invalid endpoint info structure: {endpoint_info}")
                                continue
                            
                            # Get the full endpoint record from database
                            endpoint = Endpoint.query.get(endpoint_info['id'])
                            if not endpoint:
                                logger.warning(f"Endpoint {endpoint_info['id']} not found in database")
                                continue
                            
                            # Create scan configuration for individual endpoint
                            scan_config = {
                                'scan_depth': 'standard',  # Use 'standard' instead of 'comprehensive' for compatibility
                                'timeout': 60,  # Use reasonable timeout like manual scans
                                'tools': ['zap', 'nuclei', 'sqlmap'],  # Use same tools as manual scans (exclude ssrfmap)
                                'notifications': True,
                                'save_parameters': True,
                                'auto_triggered': True,
                                'change_reason': change.get('change_type', 'unknown'),
                                'change_details': f"Endpoint {endpoint.path} ({endpoint.method}) - {change.get('change_type', 'unknown')}",
                                'target_endpoint_id': endpoint.id,  # Explicitly specify this is for a single endpoint
                                'scan_scope': 'endpoint'  # Make it clear this is endpoint-level scanning
                            }
                            
                            # Validate scan config
                            logger.info(f"🔧 Created scan config: {scan_config}")
                            
                            # Create a scan record first, then queue the task
                            from app.models import Scan
                            from datetime import datetime
                            
                            scan = Scan(
                                endpoint_id=endpoint.id,
                                scan_type='auto',
                                status='pending',
                                scan_time=datetime.now(timezone.utc),
                                scan_config=json.dumps(scan_config)
                            )
                            
                            # Use Flask app context for database operations
                            db.session.add(scan)
                            db.session.commit()
                            
                            # Queue scan task with the scan ID and raw config (not JSON string)
                            scan_endpoint.delay(scan.id, scan_config)
                            
                            logger.info(f"✅ Auto-scan queued for endpoint: {endpoint.path} ({endpoint.method})")
                            
                        except Exception as e:
                            logger.error(f"❌ Failed to queue auto-scan for endpoint {endpoint_info.get('id', 'unknown')}: {e}")
                    
                    # Send notification about auto-scanning
                    try:
                        from app.utils.slack_notifier import slack_notifier
                        # Send auto-scan notification using the new system
                        scan_data = {
                            'scan_type': 'auto',
                            'service_name': service.name,
                            'endpoint_path': f"Service-wide scan ({len(affected_endpoints)} endpoints)",
                            'endpoint_method': 'MULTIPLE',
                            'tools_used': ['ZAP', 'Nuclei', 'SQLMap'],
                            'scan_id': f"auto-{int(time.time())}",
                            'is_service_scan': True,
                            'endpoint_count': len(affected_endpoints),
                            'change_type': change['change_type'],
                            'severity': change['severity']
                        }
                        
                        slack_notifier.send_scan_started(scan_data)
                    except Exception as e:
                        logger.warning(f"Failed to send auto-scan notification: {e}")
                        
        except Exception as e:
            logger.error(f"Error triggering auto-scans: {e}")
    
    def _update_snapshots(self, current_state: Dict, changes_detected: List[Dict] = None):
        """Update snapshots with current state including endpoint details"""
        # Track which services had changes
        services_with_changes = set()
        if changes_detected:
            for change in changes_detected:
                services_with_changes.add(change['service_id'])
        
        for service_id, service_data in current_state.items():
            # Check if this service had changes
            had_changes = service_id in services_with_changes
            had_scans = had_changes and self.auto_scan_enabled
            
            snapshot = APISnapshot(
                timestamp=service_data['timestamp'],
                service_id=service_id,
                endpoint_count=service_data['endpoint_count'],
                endpoints_hash=service_data['endpoints_hash'],
                services_hash=hashlib.md5(str(service_data).encode()).hexdigest(),
                changes_detected=had_changes,  # Set based on actual changes
                scan_triggered=had_scans,      # Set based on whether scans were triggered
                endpoints=service_data.get('endpoints', []),  # Store endpoint details for comparison
                change_details=changes_detected if had_changes else None # Store actual change details
            )
            
            self.snapshots[service_id] = snapshot
    
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        return {
            'running': self.running,
            'check_interval': self.check_interval,
            'auto_scan_enabled': self.auto_scan_enabled,
            'scan_tools': self.scan_tools,
            'scan_depth': self.scan_depth,
            'change_threshold': self.change_threshold,
            'last_check': self.last_check.isoformat() if self.last_check else None,
            'services_monitored': len(self.snapshots),
            'config_file': self.config_file
        }
    
    def get_recent_changes(self, hours: int = 24) -> List[Dict]:
        """Get recent API changes with detailed information"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        changes = []
        
        for snapshot in self.snapshots.values():
            if snapshot.timestamp >= cutoff_time and snapshot.changes_detected:
                # Get detailed change information
                change_info = asdict(snapshot)
                
                # Add service name and additional context
                try:
                    from app import create_app, db
                    from app.models import Service
                    
                    app = create_app()
                    with app.app_context():
                        service = Service.query.get(snapshot.service_id)
                        if service:
                            change_info['service_name'] = service.name
                            change_info['service_url'] = service.api_url
                except Exception as e:
                    logger.warning(f"Could not get service details for {snapshot.service_id}: {e}")
                    change_info['service_name'] = f"Service {snapshot.service_id[:8]}"
                    change_info['service_url'] = "Unknown"
                
                # Extract change details from the stored change_details
                if snapshot.change_details:
                    # Use the first change detail for the main display
                    first_change = snapshot.change_details[0]
                    change_info['change_type'] = first_change.get('change_type', 'unknown')
                    change_info['details'] = first_change.get('details', 'Change detected')
                    change_info['severity'] = first_change.get('severity', 'medium')
                    change_info['affected_endpoints'] = first_change.get('affected_endpoints', [])
                    
                    # Add change summary
                    if snapshot.scan_triggered:
                        change_info['summary'] = f"Changes detected in {change_info.get('service_name', snapshot.service_id[:8])} - Auto-scan triggered"
                    else:
                        change_info['summary'] = f"Changes detected in {change_info.get('service_name', snapshot.service_id[:8])} - No auto-scan"
                else:
                    # Fallback if no change details stored
                    change_info['change_type'] = 'change_detected'
                    change_info['details'] = 'API changes detected'
                    change_info['severity'] = 'medium'
                    change_info['affected_endpoints'] = []
                    change_info['summary'] = f"Changes detected in {change_info.get('service_name', snapshot.service_id[:8])}"
                
                changes.append(change_info)
        
        return sorted(changes, key=lambda x: x['timestamp'], reverse=True)
    
    def get_scan_activity_log(self, hours: int = 24) -> List[Dict]:
        """Get recent scan activity from database"""
        try:
            from app import create_app, db
            from app.models import Scan, Endpoint, Service, Vulnerability
            
            app = create_app()
            with app.app_context():
                cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
                
                # Get recent scans with related data (all scan types, not just auto)
                scans = db.session.query(Scan, Endpoint, Service).join(
                    Endpoint, Scan.endpoint_id == Endpoint.id
                ).join(
                    Service, Endpoint.service_id == Service.id
                ).filter(
                    Scan.scan_time >= cutoff_time
                ).order_by(Scan.scan_time.desc()).limit(50).all()  # Limit to recent 50 scans
                
                scan_logs = []
                for scan, endpoint, service in scans:
                    # Get vulnerability count for this scan
                    vuln_count = db.session.query(db.func.count(Vulnerability.id)).filter(
                        Vulnerability.scan_id == scan.id
                    ).scalar() or 0
                    
                    # Check if auto-triggered
                    auto_triggered = False
                    try:
                        if scan.scan_config:
                            import json
                            config = json.loads(scan.scan_config) if isinstance(scan.scan_config, str) else scan.scan_config
                            auto_triggered = config.get('auto_triggered', False)
                    except:
                        pass
                    
                    scan_log = {
                        'scan_id': scan.id,
                        'timestamp': scan.scan_time.isoformat(),
                        'service_name': service.name,
                        'endpoint_path': endpoint.path,
                        'endpoint_method': endpoint.method,
                        'status': scan.status,
                        'scan_type': scan.scan_type,
                        'duration': scan.duration,
                        'vulnerabilities_found': vuln_count,
                        'auto_triggered': auto_triggered,
                        'tools_used': scan.tools_used,
                        'scan_config': scan.scan_config
                    }
                    scan_logs.append(scan_log)
                
                return scan_logs
                
        except Exception as e:
            logger.error(f"Error getting scan activity log: {e}")
            return []
    
    def get_baseline_status(self) -> Dict:
        """Get detailed baseline status information"""
        try:
            status = {
                'baseline_established': len(self.snapshots) > 0,
                'services_with_baseline': len(self.snapshots),
                'auto_scan_enabled': self.auto_scan_enabled,
                'last_baseline_update': None,
                'baseline_details': []
            }
            
            if self.snapshots:
                # Get the most recent snapshot timestamp
                latest_timestamp = max(snapshot.timestamp for snapshot in self.snapshots.values())
                status['last_baseline_update'] = latest_timestamp.isoformat()
                
                # Get baseline details for each service
                for service_id, snapshot in self.snapshots.items():
                    try:
                        from app import create_app, db
                        from app.models import Service
                        
                        app = create_app()
                        with app.app_context():
                            service = Service.query.get(service_id)
                            if service:
                                baseline_detail = {
                                    'service_id': service_id,
                                    'service_name': service.name,
                                    'endpoint_count': snapshot.endpoint_count,
                                    'baseline_timestamp': snapshot.timestamp.isoformat(),
                                    'changes_detected': snapshot.changes_detected,
                                    'scan_triggered': snapshot.scan_triggered
                                }
                                status['baseline_details'].append(baseline_detail)
                    except Exception as e:
                        logger.warning(f"Could not get service details for baseline: {e}")
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting baseline status: {e}")
            return {
                'baseline_established': False,
                'services_with_baseline': 0,
                'auto_scan_enabled': False,
                'last_baseline_update': None,
                'baseline_details': []
            }

# Global real-time monitor instance
realtime_monitor = RealTimeMonitor()

def start_realtime_monitoring():
    """Start real-time monitoring"""
    realtime_monitor.start_monitoring()

def stop_realtime_monitoring():
    """Stop real-time monitoring"""
    realtime_monitor.stop_monitoring()

def update_realtime_config(**kwargs):
    """Update real-time monitoring configuration"""
    realtime_monitor.update_config(**kwargs)

def get_realtime_status() -> Dict:
    """Get real-time monitoring status"""
    return realtime_monitor.get_monitoring_status()

def get_recent_changes(hours: int = 24) -> List[Dict]:
    """Get recent API changes"""
    return realtime_monitor.get_recent_changes(hours)

def get_scan_activity_log(hours: int = 24) -> List[Dict]:
    """Get recent scan activity log"""
    return realtime_monitor.get_scan_activity_log(hours)

def get_baseline_status() -> Dict:
    """Get detailed baseline status"""
    return realtime_monitor.get_baseline_status()

def establish_baseline():
    """Establish baseline snapshot without scanning"""
    return realtime_monitor.establish_baseline()

def reset_baseline():
    """Reset baseline and force re-establishment"""
    return realtime_monitor.reset_baseline()

def enable_auto_scanning():
    """Enable auto-scanning after baseline is established"""
    return realtime_monitor.enable_auto_scanning()

def disable_auto_scanning():
    """Disable auto-scanning"""
    return realtime_monitor.disable_auto_scanning()
