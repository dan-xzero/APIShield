"""
Scan Scheduler for Automated Security Scanning
"""

import logging
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from croniter import croniter
from app import db
from app.models import ScanSchedule, Service, Endpoint, Scan
from app.utils.scanner import SecurityScanner
from app.utils.slack_notifier import slack_notifier, NotificationData, NotificationType
from app.utils.enhanced_parameter_generator import EnhancedParameterGenerator

logger = logging.getLogger(__name__)

class ScanScheduler:
    """Manages automated scan scheduling and execution"""
    
    def __init__(self):
        self.scanner = SecurityScanner()
    
    def create_schedule(self, service_id: str, name: str, cron_expression: str, 
                       scan_type: str = 'combined') -> str:
        """
        Create a new scan schedule
        
        Args:
            service_id: ID of the service to schedule scans for
            name: Name of the schedule
            cron_expression: Cron expression for scheduling
            scan_type: Type of scan to run
            
        Returns:
            Schedule ID
        """
        try:
            # Validate cron expression
            if not self._validate_cron_expression(cron_expression):
                raise ValueError("Invalid cron expression")
            
            # Calculate next run time
            next_run = self._calculate_next_run(cron_expression)
            
            # Create schedule
            schedule = ScanSchedule(
                service_id=service_id,
                name=name,
                cron_expression=cron_expression,
                scan_type=scan_type,
                next_run=next_run
            )
            
            db.session.add(schedule)
            db.session.commit()
            
            logger.info(f"✅ Created scan schedule: {schedule.id} - {name}")
            return schedule.id
            
        except Exception as e:
            logger.error(f"❌ Failed to create scan schedule: {e}")
            db.session.rollback()
            raise
    
    def update_schedule(self, schedule_id: str, **kwargs) -> bool:
        """Update an existing scan schedule"""
        try:
            schedule = ScanSchedule.query.get(schedule_id)
            if not schedule:
                raise ValueError("Schedule not found")
            
            # Update fields
            for key, value in kwargs.items():
                if hasattr(schedule, key):
                    setattr(schedule, key, value)
            
            # Recalculate next run if cron expression changed
            if 'cron_expression' in kwargs:
                if not self._validate_cron_expression(kwargs['cron_expression']):
                    raise ValueError("Invalid cron expression")
                schedule.next_run = self._calculate_next_run(kwargs['cron_expression'])
            
            schedule.updated_at = datetime.now(timezone.utc)
            db.session.commit()
            
            logger.info(f"✅ Updated scan schedule: {schedule_id}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to update scan schedule: {e}")
            db.session.rollback()
            return False
    
    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a scan schedule"""
        try:
            schedule = ScanSchedule.query.get(schedule_id)
            if not schedule:
                return False
            
            db.session.delete(schedule)
            db.session.commit()
            
            logger.info(f"✅ Deleted scan schedule: {schedule_id}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to delete scan schedule: {e}")
            db.session.rollback()
            return False
    
    def get_schedules(self, service_id: str = None, active_only: bool = True) -> List[Dict]:
        """Get scan schedules"""
        try:
            query = ScanSchedule.query
            
            if service_id:
                query = query.filter_by(service_id=service_id)
            
            if active_only:
                query = query.filter_by(is_active=True)
            
            schedules = query.all()
            
            return [{
                'id': s.id,
                'name': s.name,
                'service_id': s.service_id,
                'service_name': s.service.name if s.service else None,
                'cron_expression': s.cron_expression,
                'scan_type': s.scan_type,
                'is_active': s.is_active,
                'last_run': s.last_run.isoformat() if s.last_run else None,
                'next_run': s.next_run.isoformat() if s.next_run else None,
                'created_at': s.created_at.isoformat(),
                'updated_at': s.updated_at.isoformat()
            } for s in schedules]
            
        except Exception as e:
            logger.error(f"❌ Failed to get scan schedules: {e}")
            return []
    
    def run_due_scans(self) -> List[Dict]:
        """Run all scans that are due"""
        try:
            now = datetime.now(timezone.utc)
            due_schedules = ScanSchedule.query.filter(
                ScanSchedule.is_active == True,
                ScanSchedule.next_run <= now
            ).all()
            
            results = []
            
            for schedule in due_schedules:
                try:
                    logger.info(f"🔍 Running scheduled scan: {schedule.name}")
                    
                    # Run the scan
                    scan_result = self._run_scheduled_scan(schedule)
                    
                    # Update schedule
                    schedule.last_run = now
                    schedule.next_run = self._calculate_next_run(schedule.cron_expression)
                    schedule.updated_at = now
                    
                    results.append({
                        'schedule_id': schedule.id,
                        'schedule_name': schedule.name,
                        'success': scan_result['success'],
                        'scans_run': scan_result['scans_run'],
                        'vulnerabilities_found': scan_result['vulnerabilities_found'],
                        'error': scan_result.get('error')
                    })
                    
                except Exception as e:
                    logger.error(f"❌ Failed to run scheduled scan {schedule.id}: {e}")
                    results.append({
                        'schedule_id': schedule.id,
                        'schedule_name': schedule.name,
                        'success': False,
                        'error': str(e)
                    })
            
            db.session.commit()
            return results
            
        except Exception as e:
            logger.error(f"❌ Failed to run due scans: {e}")
            db.session.rollback()
            return []
    
    def _run_scheduled_scan(self, schedule: ScanSchedule) -> Dict:
        """Run a scheduled scan for a service"""
        try:
            service = schedule.service
            if not service:
                raise ValueError("Service not found")
            
            # Get endpoints for the service
            endpoints = Endpoint.query.filter_by(service_id=service.id).all()
            
            if not endpoints:
                return {
                    'success': True,
                    'scans_run': 0,
                    'vulnerabilities_found': 0,
                    'message': 'No endpoints found for service'
                }
            
            scans_run = 0
            vulnerabilities_found = 0
            
            # Run scans for each endpoint
            for endpoint in endpoints:
                try:
                    # Generate parameters for the endpoint
                    from app.utils.enhanced_parameter_generator import EnhancedParameterGenerator
                    param_generator = EnhancedParameterGenerator()
                    
                    param_result = param_generator.generate_and_validate_parameters(endpoint)
                    
                    if param_result['validation']['success']:
                        # Run security scan
                        scan_result = self.scanner.scan_endpoint(
                            endpoint.__dict__,
                            param_result['parameters'],
                            schedule.scan_type
                        )
                        
                        # Store scan result
                        scan = Scan(
                            endpoint_id=endpoint.id,
                            scan_type=schedule.scan_type,
                            status='completed',
                            results=json.dumps(scan_result),
                            tools_used=','.join(scan_result.get('tools_used', []))
                        )
                        db.session.add(scan)
                        
                        # Count vulnerabilities
                        vuln_count = len(scan_result.get('vulnerabilities', []))
                        vulnerabilities_found += vuln_count
                        scans_run += 1
                        
                        logger.info(f"   ✅ Scanned {endpoint.path}: {vuln_count} vulnerabilities")
                    else:
                        logger.warning(f"   ⚠️  Skipped {endpoint.path}: parameter validation failed")
                        
                except Exception as e:
                    logger.error(f"   ❌ Failed to scan {endpoint.path}: {e}")
            
            return {
                'success': True,
                'scans_run': scans_run,
                'vulnerabilities_found': vulnerabilities_found
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to run scheduled scan: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _validate_cron_expression(self, cron_expression: str) -> bool:
        """Validate cron expression"""
        try:
            croniter(cron_expression)
            return True
        except Exception:
            return False
    
    def _calculate_next_run(self, cron_expression: str) -> datetime:
        """Calculate next run time based on cron expression"""
        try:
            cron = croniter(cron_expression, datetime.now(timezone.utc))
            return cron.get_next(datetime)
        except Exception as e:
            logger.error(f"❌ Failed to calculate next run: {e}")
            return datetime.now(timezone.utc) + timedelta(hours=1)
    
    def get_schedule_stats(self) -> Dict:
        """Get statistics about scan schedules"""
        try:
            total_schedules = ScanSchedule.query.count()
            active_schedules = ScanSchedule.query.filter_by(is_active=True).count()
            
            # Get schedules due in next 24 hours
            next_24h = datetime.now(timezone.utc) + timedelta(hours=24)
            due_soon = ScanSchedule.query.filter(
                ScanSchedule.is_active == True,
                ScanSchedule.next_run <= next_24h
            ).count()
            
            # Get recent runs
            last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
            recent_runs = ScanSchedule.query.filter(
                ScanSchedule.last_run >= last_24h
            ).count()
            
            return {
                'total_schedules': total_schedules,
                'active_schedules': active_schedules,
                'due_soon': due_soon,
                'recent_runs': recent_runs
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to get schedule stats: {e}")
            return {}
    
    def pause_schedule(self, schedule_id: str) -> bool:
        """Pause a scan schedule"""
        return self.update_schedule(schedule_id, is_active=False)
    
    def resume_schedule(self, schedule_id: str) -> bool:
        """Resume a scan schedule"""
        return self.update_schedule(schedule_id, is_active=True)
    
    def run_schedule_now(self, schedule_id: str) -> Dict:
        """Run a schedule immediately"""
        try:
            schedule = ScanSchedule.query.get(schedule_id)
            if not schedule:
                return {'success': False, 'error': 'Schedule not found'}
            
            # Send schedule execution notification
            service_name = schedule.service.name if schedule.service else 'Unknown Service'
            # Send schedule execution notification using the new system
            notification_data = NotificationData(
                type=NotificationType.SCAN_STARTED,
                title='Scheduled Scan Executed',
                message=f'Scheduled scan "{schedule.name}" executed for service: {service_name}',
                severity='info',
                data={
                    'schedule_name': schedule.name,
                    'service_name': service_name,
                    'timestamp': datetime.now().isoformat()
                }
            )
            slack_notifier.send_notification(notification_data)
            
            # Run the scan
            result = self._run_scheduled_scan(schedule)
            
            # Update last run time
            schedule.last_run = datetime.now(timezone.utc)
            schedule.next_run = self._calculate_next_run(schedule.cron_expression)
            schedule.updated_at = datetime.now(timezone.utc)
            
            db.session.commit()
            
            # Send final schedule execution notification with results
            scans_run = result.get('scans_run', 0)
            vulnerabilities_found = result.get('vulnerabilities_found', 0)
            
            notification_data = NotificationData(
                type=NotificationType.SCAN_COMPLETED,
                title='Scheduled Scan Completed',
                message=f'Scheduled scan "{schedule.name}" completed for {service_name}: {vulnerabilities_found} vulnerabilities found',
                severity='warning' if vulnerabilities_found > 0 else 'info',
                data={
                    'schedule_name': schedule.name,
                    'service_name': service_name,
                    'scans_run': scans_run,
                    'vulnerabilities_found': vulnerabilities_found,
                    'timestamp': datetime.now().isoformat()
                }
            )
            slack_notifier.send_notification(notification_data)
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Failed to run schedule now: {e}")
            db.session.rollback()
            
            # Send system error notification
            slack_notifier.send_system_error(
                "Schedule Execution Failed",
                f"Schedule '{schedule.name if 'schedule' in locals() else 'Unknown'}' execution failed: {e}",
                {'schedule_id': schedule_id}
            )
            
            return {'success': False, 'error': str(e)}
