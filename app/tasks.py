"""
Celery tasks for background processing
"""

import logging
from datetime import datetime, timedelta, timezone
from celery import Celery
from app import create_app, db
from app.models import Service, ApiVersion, Endpoint, Scan, Vulnerability, ScanTarget
from app.utils.crawler import APIPortalCrawler
from app.utils.placeholder import ParameterGenerator
from app.utils.scanner import SecurityScanner
# from app.utils.slack_client import SlackNotifier  # Removed slack integration
from app.config import Config
import json
import time
import sqlalchemy.exc as sa_exc

# Create Celery instance
celery = Celery('api_scanner')

# Configure Celery
celery.conf.update(
    broker_url=Config.REDIS_URL,
    result_backend=Config.REDIS_URL,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=1800,  # 30 minutes
    task_soft_time_limit=900,  # 15 minutes
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)

logger = logging.getLogger(__name__)

def safe_db_operation(operation_func, max_retries=3, retry_delay=1):
    """
    Safely execute database operations with retry logic for database locking issues
    
    Args:
        operation_func: Function that performs the database operation
        max_retries: Maximum number of retry attempts
        retry_delay: Delay between retries in seconds
    
    Returns:
        Result of the operation function
    """
    for attempt in range(max_retries):
        try:
            return operation_func()
        except (sa_exc.OperationalError, sa_exc.PendingRollbackError) as e:
            if "database is locked" in str(e).lower() or "pendingrollback" in str(e).lower():
                if attempt < max_retries - 1:
                    logger.warning(f"⚠️  Database locked on attempt {attempt + 1}/{max_retries}, retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    # Rollback and create new session
                    try:
                        db.session.rollback()
                    except:
                        pass
                    continue
                else:
                    logger.error(f"❌ Database operation failed after {max_retries} attempts: {e}")
                    raise
            else:
                raise
        except Exception as e:
            logger.error(f"❌ Database operation failed: {e}")
            raise

def update_scan_status(scan_id, status, **kwargs):
    """
    Safely update scan status with retry logic
    
    Args:
        scan_id: ID of the scan to update
        status: New status for the scan
        **kwargs: Additional fields to update
    """
    def update_operation():
        scan = Scan.query.get(scan_id)
        if scan:
            scan.status = status
            for key, value in kwargs.items():
                if hasattr(scan, key):
                    setattr(scan, key, value)
            db.session.commit()
            return True
        return False
    
    return safe_db_operation(update_operation)

@celery.task(bind=True)
def crawl_and_update_services(self):
    """
    Crawl the API Change Tracker and update services database
    """
    try:
        logger.info("Starting service discovery and update")
        
        # Create Flask app context
        app = create_app()
        with app.app_context():
            crawler = APIPortalCrawler()
            stats = crawler.update_services_database()
            
            logger.info(f"Service update completed: {stats}")
            
            # Send notification if new services or endpoints found
            # if stats['services_discovered'] > 0 or stats['endpoints_added'] > 0:
            #     # notifier = SlackNotifier()  # Removed slack integration
            #     # notifier.send_daily_summary({
            #     #     'services_discovered': stats['services_discovered'],
            #     #     'endpoints_added': stats['endpoints_added'],
            #     #     'services_updated': stats['services_updated'],
            #     #     'services_failed': stats['services_failed']
            #     # })
            
            return stats
            
    except Exception as e:
        logger.error(f"Service discovery failed: {e}")
        raise

@celery.task(bind=True)
def scan_endpoint(self, scan_id: str, scan_config: dict = None):
    """
    Scan a specific endpoint for vulnerabilities
    
    Args:
        scan_id: ID of the scan record to update
        scan_config: Scan configuration dictionary
    """
    try:
        logger.info(f"🚀 Starting scan for scan ID {scan_id}")
        logger.info(f"   Scan config: {scan_config}")
        logger.info(f"   Task ID: {self.request.id}")
        
        # Create Flask app context
        app = create_app()
        with app.app_context():
            # Get scan record from database
            logger.info(f"🔍 Fetching scan record from database...")
            
            def get_scan_operation():
                scan = Scan.query.get(scan_id)
                if not scan:
                    logger.error(f"❌ Scan {scan_id} not found")
                    return None
                return scan
            
            scan = safe_db_operation(get_scan_operation)
            if not scan:
                return {'error': 'Scan not found'}
            
            # Get endpoint from scan
            endpoint = scan.endpoint
            if not endpoint:
                logger.error(f"❌ Endpoint not found for scan {scan_id}")
                return {'error': 'Endpoint not found'}
            
            logger.info(f"✅ Endpoint found: {endpoint.path} ({endpoint.method})")
            logger.info(f"   Service: {endpoint.service.name if endpoint.service else 'Unknown'}")
            logger.info(f"   Risk Score: {endpoint.risk_score}")
            
            # Update scan record with scan configuration
            if scan_config:
                def update_config_operation():
                    # Ensure scan_config is a dictionary
                    if isinstance(scan_config, str):
                        try:
                            scan_config_dict = json.loads(scan_config)
                        except json.JSONDecodeError:
                            scan_config_dict = {}
                    elif isinstance(scan_config, dict):
                        scan_config_dict = scan_config
                    else:
                        scan_config_dict = {}
                    
                    scan.scan_config = json.dumps(scan_config_dict)
                    scan.tools_used = ','.join(scan_config_dict.get('tools', []))
                    db.session.commit()
                    return True
                
                safe_db_operation(update_config_operation)
                logger.info(f"✅ Updated scan record with configuration")
            
            try:
                # Generate parameter values
                logger.info(f"🔧 Generating parameter values...")
                generator = ParameterGenerator()
                
                # Parse JSON strings from database if needed
                parameters_schema = endpoint.parameters_schema
                request_body_schema = endpoint.request_body_schema
                
                if isinstance(parameters_schema, str):
                    try:
                        parameters_schema = json.loads(parameters_schema) if parameters_schema else {}
                    except json.JSONDecodeError:
                        logger.warning(f"⚠️ Failed to parse parameters_schema JSON: {parameters_schema}")
                        parameters_schema = {}
                
                if isinstance(request_body_schema, str):
                    try:
                        request_body_schema = json.loads(request_body_schema) if request_body_schema else {}
                    except json.JSONDecodeError:
                        logger.warning(f"⚠️ Failed to parse request_body_schema JSON: {request_body_schema}")
                        request_body_schema = {}
                
                # Prepare endpoint data for parameter generation
                endpoint_for_params = {
                    'path': endpoint.path,
                    'method': endpoint.method,
                    'summary': getattr(endpoint, 'summary', ''),
                    'description': getattr(endpoint, 'description', ''),
                    'parameters_schema': parameters_schema,
                    'request_body_schema': request_body_schema
                }
                
                # Debug logging to see what we're passing
                logger.info(f"🔍 Debug - endpoint_for_params type: {type(endpoint_for_params)}")
                logger.info(f"🔍 Debug - endpoint_for_params content: {endpoint_for_params}")
                logger.info(f"🔍 Debug - parameters_schema type: {type(parameters_schema)}")
                logger.info(f"🔍 Debug - request_body_schema type: {type(request_body_schema)}")
                
                param_values = generator.generate_parameter_values(endpoint_for_params, use_ai=True)
                logger.info(f"✅ Generated {len(param_values)} parameter values: {list(param_values.keys())}")
                
                # Update scan with parameter values
                def update_params_operation():
                    scan.param_values_used = param_values
                    db.session.commit()
                    return True
                
                safe_db_operation(update_params_operation)
                logger.info(f"✅ Updated scan record with parameter values")
                
                # Prepare endpoint data for scanner
                logger.info(f"🔧 Preparing endpoint data for scanner...")
                endpoint_data = {
                    'path': endpoint.path,
                    'method': endpoint.method,
                    'service_name': endpoint.service.name,
                    'parameters_schema': parameters_schema,
                    'request_body_schema': request_body_schema
                }
                logger.info(f"✅ Endpoint data prepared: {endpoint_data['path']} ({endpoint_data['method']})")
                
                # Run security scan
                logger.info(f"🚀 Initializing SecurityScanner...")
                scanner = SecurityScanner()
                
                # Determine which tools to use based on scan configuration
                # Ensure scan_config is a dictionary
                if isinstance(scan_config, str):
                    try:
                        scan_config_dict = json.loads(scan_config)
                    except json.JSONDecodeError:
                        scan_config_dict = {}
                elif isinstance(scan_config, dict):
                    scan_config_dict = scan_config
                else:
                    scan_config_dict = {}
                
                tools_to_use = scan_config_dict.get('tools', ['zap', 'nuclei'])
                logger.info(f"🔍 Starting security scan with tools: {tools_to_use}")
                
                # Send scan started notification
                try:
                    from app.utils.slack_notifier import slack_notifier
                    
                    # Check if this is an auto-triggered scan
                    is_auto_scan = scan_config_dict.get('auto_triggered', False)
                    scan_type = 'Auto-Scan' if is_auto_scan else 'Manual Scan'
                    
                    # Prepare scan data for notification
                    scan_data = {
                        'scan_type': scan_type.lower().replace('-', '_'),
                        'service_name': endpoint.service.name if endpoint.service else 'Unknown',
                        'endpoint_path': endpoint.path,
                        'endpoint_method': endpoint.method,
                        'tools_used': tools_to_use,
                        'scan_id': str(scan.id),
                        'is_service_scan': False
                    }
                    
                    slack_notifier.send_scan_started(scan_data)
                    logger.info(f"✅ Scan started notification sent")
                except Exception as e:
                    logger.warning(f"⚠️ Failed to send scan started notification: {e}")
                
                # Run scans for each selected tool
                scan_results = {
                    'vulnerabilities': [],
                    'tools_used': [],
                    'duration': 0,
                    'status': 'completed'
                }
                
                start_time = time.time()
                scan_timeout = scan_config_dict.get('timeout', 60)  # Default 60 seconds
                
                for tool in tools_to_use:
                    try:
                        logger.info(f"🔍 Running {tool} scan with timeout {scan_timeout}s...")
                        
                        # Create a copy of scan_config with tool-specific timeout
                        tool_config = scan_config_dict.copy() if scan_config_dict else {}
                        tool_config['timeout'] = min(scan_timeout, 120)  # Cap at 120 seconds per tool
                        
                        if tool == 'zap':
                            tool_results = scanner._run_zap_scan(endpoint_data, param_values)
                        elif tool == 'nuclei':
                            tool_results = scanner._run_nuclei_scan(endpoint_data, param_values)
                        elif tool == 'sqlmap':
                            tool_results = scanner._run_sqlmap_scan(endpoint_data, param_values)
                        elif tool == 'ssrfmap':
                            tool_results = scanner._run_ssrfmap_scan(endpoint_data, param_values)
                        else:
                            logger.warning(f"⚠️  Unknown tool: {tool}, skipping")
                            continue
                        
                        # Check if tool scan was successful
                        if tool_results.get('error'):
                            logger.warning(f"⚠️  {tool} scan failed: {tool_results['error']}")
                            continue
                        
                        scan_results['vulnerabilities'].extend(tool_results.get('vulnerabilities', []))
                        scan_results['tools_used'].append(tool)
                        logger.info(f"✅ {tool} scan completed with {len(tool_results.get('vulnerabilities', []))} vulnerabilities")
                        
                    except Exception as e:
                        logger.error(f"❌ {tool} scan failed: {e}")
                        continue
                
                scan_results['duration'] = time.time() - start_time
                logger.info(f"✅ Security scan completed in {scan_results['duration']:.2f}s")
                
                # Update scan record with results
                logger.info(f"📝 Updating scan record with results...")
                update_scan_status(
                    scan_id=scan.id,
                    status='completed',
                    completed_at=datetime.now(timezone.utc),
                    duration=scan_results.get('duration', 0),
                    tools_used=scan_results.get('tools_used', [])
                )
                logger.info(f"✅ Scan record updated - Duration: {scan_results.get('duration', 0):.2f}s, Tools: {scan_results.get('tools_used', [])}")
                
                # Store vulnerabilities
                vulnerabilities = scan_results.get('vulnerabilities', [])
                logger.info(f"🚨 Processing {len(vulnerabilities)} vulnerabilities...")
                
                if vulnerabilities:
                    def store_vulnerabilities_operation():
                        new_vulns = 0
                        existing_vulns = 0
                        
                        for i, vuln_data in enumerate(vulnerabilities):
                            logger.info(f"   📝 Processing vulnerability {i+1}: {vuln_data.get('name', 'Unknown')} ({vuln_data.get('severity', 'medium')})")
                            
                            # Use the new duplicate prevention logic
                            vulnerability, is_new = Vulnerability.find_or_create_vulnerability(
                                scan_id=scan.id,
                                endpoint_id=endpoint.id,
                                service_id=endpoint.service.id,
                                name=vuln_data.get('name', 'Unknown'),
                                description=vuln_data.get('description', ''),
                                severity=vuln_data.get('severity', 'medium'),
                                category=vuln_data.get('category', 'other'),
                                details=vuln_data.get('details', {}),
                                evidence=vuln_data.get('evidence', ''),
                                tool_used=vuln_data.get('tool', 'unknown'),
                                cvss_score=vuln_data.get('cvss_score'),
                                risk_score=vuln_data.get('risk_score', 0.0)
                            )
                            
                            if is_new:
                                new_vulns += 1
                                logger.info(f"      ✅ New vulnerability stored")
                            else:
                                existing_vulns += 1
                                logger.info(f"      🔄 Existing vulnerability updated (occurrence #{vulnerability.occurrence_count})")
                        
                        logger.info(f"📊 Vulnerability summary: {new_vulns} new, {existing_vulns} existing")
                        return True
                    
                    safe_db_operation(store_vulnerabilities_operation)
                    logger.info(f"✅ All vulnerabilities processed with duplicate prevention")
                
                # Send Slack notification
                logger.info(f"📢 Sending Slack notification...")
                try:
                    from app.utils.slack_notifier import slack_notifier
                    
                    # Prepare scan completion data for notification
                    completion_data = {
                        'scan_type': scan_type.lower().replace('-', '_'),
                        'service_name': endpoint.service.name if endpoint.service else 'Unknown',
                        'endpoint_path': endpoint.path,
                        'endpoint_method': endpoint.method,
                        'scan_id': str(scan.id),
                        'duration': scan_results.get('duration', 0),
                        'tools_used': scan_results.get('tools_used', []),
                        'vulnerabilities': vulnerabilities,
                        'is_service_scan': False
                    }
                    
                    slack_notifier.send_scan_completed(completion_data)
                    
                    # Send individual vulnerability alerts only for high-risk findings
                    # The SlackNotifier now handles deduplication automatically
                    for vuln in vulnerabilities:
                        if vuln.get('severity', '').lower() in ['high', 'critical']:
                            vuln['scan_id'] = str(scan.id)
                            slack_notifier.send_vulnerability_alert(vuln)
                    logger.info(f"✅ Slack notification sent")
                except Exception as e:
                    logger.warning(f"⚠️ Failed to send Slack notification: {e}")
                
                logger.info(f"🎉 Scan completed for endpoint {endpoint.id}: {len(vulnerabilities)} vulnerabilities found")
                
                return {
                    'scan_id': scan.id,
                    'vulnerabilities_found': len(vulnerabilities),
                    'duration': scan_results.get('duration', 0)
                }
                
            except Exception as e:
                # Update scan status to failed
                update_scan_status(
                    scan_id=scan.id,
                    status='failed',
                    completed_at=datetime.now(timezone.utc)
                )
                logger.error(f"❌ Endpoint scan task failed: {e}")
                raise
                
    except Exception as e:
        logger.error(f"Endpoint scan task failed: {e}")
        raise

@celery.task(bind=True)
def scan_changed_endpoints(self):
    """
    Scan all endpoints that have been changed or added recently
    """
    try:
        logger.info("Starting scan of changed endpoints")
        
        # Create Flask app context
        app = create_app()
        with app.app_context():
            # Get endpoints that need scanning
            scan_targets = ScanTarget.query.filter_by(priority__gte=1).all()
            
            if not scan_targets:
                logger.info("No endpoints need scanning")
                return {'scanned': 0, 'vulnerabilities_found': 0}
            
            total_vulnerabilities = 0
            scanned_count = 0
            
            for target in scan_targets:
                try:
                    # NOTE: Automatic scanning is now handled by real-time monitoring
                    # Only create scan records when explicitly requested
                    # scan_endpoint.delay(target.endpoint_id, 'combined')  # DISABLED
                    scanned_count += 1
                    
                    # Remove from scan targets
                    db.session.delete(target)
                    
                except Exception as e:
                    logger.error(f"Failed to process endpoint {target.endpoint_id}: {e}")
            
            db.session.commit()
            
            logger.info(f"Queued {scanned_count} endpoints for scanning")
            return {'scanned': scanned_count, 'vulnerabilities_found': total_vulnerabilities}
            
    except Exception as e:
        logger.error(f"Changed endpoints scan failed: {e}")
        raise

@celery.task(bind=True)
def generate_daily_summary(self):
    """
    Generate and send daily summary of security findings
    """
    try:
        logger.info("Generating daily summary")
        
        # Create Flask app context
        app = create_app()
        with app.app_context():
            # Get today's date
            today = datetime.now(timezone.utc).date()
            
            # Get scans from today
            today_scans = Scan.query.filter(
                Scan.scan_time >= today,
                Scan.status == 'completed'
            ).all()
            
            # Get vulnerabilities from today
            today_vulnerabilities = Vulnerability.query.join(Scan).filter(
                Scan.scan_time >= today
            ).all()
            
            # Count by severity
            severity_counts = {}
            for vuln in today_vulnerabilities:
                severity = vuln.severity
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Get unique services and endpoints
            services_scanned = len(set(scan.endpoint.service_id for scan in today_scans))
            endpoints_scanned = len(set(scan.endpoint_id for scan in today_scans))
            
            summary_data = {
                'total_scans': len(today_scans),
                'total_vulnerabilities': len(today_vulnerabilities),
                'services_scanned': services_scanned,
                'endpoints_scanned': endpoints_scanned,
                'severity_counts': severity_counts
            }
            
            # Send Slack notification
            # # notifier = SlackNotifier()  # Removed slack integration
            # # dashboard_url = "http://localhost:5000/dashboard"
            # # notifier.send_daily_summary(summary_data, dashboard_url)
            
            logger.info(f"Daily summary sent: {summary_data}")
            return summary_data
            
    except Exception as e:
        logger.error(f"Daily summary generation failed: {e}")
        raise

@celery.task(bind=True)
def cleanup_old_data(self, days: int = 30):
    """
    Clean up old scan data and logs
    
    Args:
        days: Number of days to keep data
    """
    try:
        logger.info(f"Cleaning up data older than {days} days")
        
        # Create Flask app context
        app = create_app()
        with app.app_context():
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            # Delete old scans and related data
            old_scans = Scan.query.filter(Scan.scan_time < cutoff_date).all()
            
            for scan in old_scans:
                # Delete related vulnerabilities
                Vulnerability.query.filter_by(scan_id=scan.id).delete()
                # Delete scan
                db.session.delete(scan)
            
            # Delete old scan targets
            ScanTarget.query.filter(ScanTarget.created_at < cutoff_date).delete()
            
            db.session.commit()
            
            logger.info(f"Cleaned up {len(old_scans)} old scans")
            return {'cleaned_scans': len(old_scans)}
            
    except Exception as e:
        logger.error(f"Data cleanup failed: {e}")
        raise

# @celery.task(bind=True)
# def test_slack_integration(self):
#     """
#     Test Slack integration by sending a test message
#     """
#     try:
#         logger.info("Testing Slack integration")
#         
#         # notifier = SlackNotifier()  # Removed slack integration
#         # success = notifier.send_test_message()
#         
#         if success:
#             logger.info("Slack integration test failed")
#             return {'status': 'failed'}
#             
#     except Exception as e:
#         logger.error(f"Slack integration test failed: {e}")
#         raise

@celery.task(bind=True)
def cleanup_stuck_scans(self):
    """
    Clean up scans that are stuck in RUNNING status for too long
    """
    try:
        logger.info("🧹 Starting cleanup of stuck scans...")
        
        app = create_app()
        with app.app_context():
            # Find scans that have been running for more than 30 minutes
            cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=30)
            
            def find_stuck_scans_operation():
                stuck_scans = Scan.query.filter(
                    Scan.status == 'running',
                    Scan.scan_time < cutoff_time
                ).all()
                return stuck_scans
            
            stuck_scans = safe_db_operation(find_stuck_scans_operation)
            
            if not stuck_scans:
                logger.info("✅ No stuck scans found")
                return {'cleaned': 0}
            
            logger.info(f"🔍 Found {len(stuck_scans)} stuck scans")
            
            cleaned_count = 0
            for scan in stuck_scans:
                try:
                    def mark_failed_operation():
                        scan.status = 'failed'
                        scan.completed_at = datetime.now(timezone.utc)
                        scan.duration = 0
                        db.session.commit()
                        return True
                    
                    safe_db_operation(mark_failed_operation)
                    cleaned_count += 1
                    logger.info(f"✅ Marked scan {scan.id} as failed")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to clean up scan {scan.id}: {e}")
                    continue
            
            logger.info(f"🧹 Cleanup completed: {cleaned_count} scans marked as failed")
            return {'cleaned': cleaned_count}
            
    except Exception as e:
        logger.error(f"Cleanup task failed: {e}")
        raise

@celery.task(bind=True)
def retry_failed_scans(self, max_retries=3):
    """
    Retry scans that have failed, up to a maximum number of retries
    """
    try:
        logger.info("🔄 Starting retry of failed scans...")
        
        app = create_app()
        with app.app_context():
            # Find scans that have failed and haven't exceeded max retries
            def find_failed_scans_operation():
                failed_scans = Scan.query.filter(
                    Scan.status == 'failed'
                ).all()
                return failed_scans
            
            failed_scans = safe_db_operation(find_failed_scans_operation)
            
            if not failed_scans:
                logger.info("✅ No failed scans found")
                return {'retried': 0}
            
            logger.info(f"🔍 Found {len(failed_scans)} failed scans")
            
            retried_count = 0
            for scan in failed_scans:
                try:
                    # Check if we should retry this scan
                    if hasattr(scan, 'retry_count') and scan.retry_count >= max_retries:
                        logger.info(f"⏭️  Scan {scan.id} has exceeded max retries, skipping")
                        continue
                    
                    # Reset scan for retry
                    def reset_scan_operation():
                        scan.status = 'pending'
                        scan.scan_time = datetime.now(timezone.utc)
                        scan.completed_at = None
                        scan.duration = None
                        if hasattr(scan, 'retry_count'):
                            scan.retry_count = (scan.retry_count or 0) + 1
                        db.session.commit()
                        return True
                    
                    safe_db_operation(reset_scan_operation)
                    
                    # Queue the scan for retry
                    scan_endpoint.delay(scan.id, scan.scan_config)
                    retried_count += 1
                    logger.info(f"🔄 Queued scan {scan.id} for retry")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to retry scan {scan.id}: {e}")
                    continue
            
            logger.info(f"🔄 Retry task completed: {retried_count} scans queued for retry")
            return {'retried': retried_count}
            
    except Exception as e:
        logger.error(f"Retry task failed: {e}")
        raise


@celery.task
def retry_pending_scans():
    """Retry scans that are stuck in pending status"""
    logger.info("🔄 Starting retry of pending scans...")
    
    try:
        app = create_app()
        with app.app_context():
            # Find all pending scans
            def find_pending_scans_operation():
                pending_scans = Scan.query.filter_by(status='pending').all()
                return pending_scans
            
            pending_scans = safe_db_operation(find_pending_scans_operation)
            
            if not pending_scans:
                logger.info("✅ No pending scans found")
                return {'retried': 0}
            
            logger.info(f"🔍 Found {len(pending_scans)} pending scans")
            
            retried_count = 0
            for scan in pending_scans:
                try:
                    # Parse scan config to get scan type
                    scan_config = {}
                    if scan.scan_config:
                        try:
                            scan_config = json.loads(scan.scan_config) if isinstance(scan.scan_config, str) else scan.scan_config
                        except (json.JSONDecodeError, TypeError):
                            scan_config = {}
                    
                    # Re-queue the scan task
                    scan_endpoint.delay(scan.id, scan.scan_config)
                    retried_count += 1
                    logger.info(f"✅ Re-queued pending scan {scan.id} for endpoint {scan.endpoint_id}")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to retry pending scan {scan.id}: {e}")
                    continue
            
            logger.info(f"✅ Successfully re-queued {retried_count} pending scans")
            return {'retried': retried_count}
            
    except Exception as e:
        logger.error(f"Retry pending scans task failed: {e}")
        raise


# Scheduled tasks
@celery.task
def scheduled_service_discovery():
    """Scheduled task to discover and update services"""
    return crawl_and_update_services.delay()

@celery.task
def scheduled_endpoint_scanning():
    """Scheduled task to scan changed endpoints"""
    return scan_changed_endpoints.delay()

@celery.task
def scheduled_daily_summary():
    """Scheduled task to generate daily summary"""
    return generate_daily_summary.delay()

@celery.task
def scheduled_cleanup():
    """Scheduled task to cleanup old data"""
    return cleanup_old_data.delay(days=30)

# Configure periodic tasks
celery.conf.beat_schedule = {
    # DISABLED: Automatic service discovery is now handled by real-time monitoring
    # 'discover-services-every-6-hours': {
    #     'task': 'app.tasks.scheduled_service_discovery',
    #     'schedule': 21600.0,  # 6 hours
    # },
    # DISABLED: Automatic endpoint scanning is now handled by real-time monitoring
    # 'scan-changed-endpoints-every-hour': {
    #     'task': 'app.tasks.scheduled_endpoint_scanning',
    #     'schedule': 3600.0,  # 1 hour
    # },
    'daily-summary-at-midnight': {
        'task': 'app.tasks.scheduled_daily_summary',
        'schedule': 86400.0,  # 24 hours
    },
    'cleanup-old-data-weekly': {
        'task': 'app.tasks.scheduled_cleanup',
        'schedule': 604800.0,  # 7 days
    },
}
