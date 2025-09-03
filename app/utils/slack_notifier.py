#!/usr/bin/env python3
"""
Slack Notification System for API Security Scanner
"""

import os
import json
import logging
import requests
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import time

logger = logging.getLogger(__name__)

class NotificationType(Enum):
    """Types of notifications"""
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    VULNERABILITY_FOUND = "vulnerability_found"
    HIGH_RISK_VULNERABILITY = "high_risk_vulnerability"
    SCHEDULE_EXECUTED = "schedule_executed"
    SYSTEM_ERROR = "system_error"
    DAILY_SUMMARY = "daily_summary"

@dataclass
class NotificationData:
    """Data structure for notifications"""
    type: NotificationType
    title: str
    message: str
    severity: str = "info"  # info, warning, error, critical
    data: Optional[Dict] = None
    timestamp: Optional[datetime] = None

class SlackNotifier:
    """Slack notification system"""
    
    def __init__(self):
        self.webhook_url = os.getenv('SLACK_WEBHOOK_URL')
        self.channel = os.getenv('SLACK_CHANNEL', '#api-security')
        self.username = os.getenv('SLACK_USERNAME', 'API Security Scanner')
        self.icon_emoji = os.getenv('SLACK_ICON_EMOJI', ':shield:')
        self.enabled = bool(self.webhook_url)
        
        if not self.enabled:
            logger.warning("⚠️  Slack notifications disabled - SLACK_WEBHOOK_URL not configured")
        else:
            logger.info("✅ Slack notifications enabled")
    
    def send_notification(self, notification: NotificationData) -> bool:
        """Send a notification to Slack"""
        if not self.enabled:
            logger.debug(f"Slack disabled, skipping notification: {notification.title}")
            return False
        
        try:
            payload = self._build_payload(notification)
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Slack notification sent: {notification.title}")
                return True
            else:
                logger.error(f"❌ Slack notification failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Slack notification error: {e}")
            return False
    
    def _build_payload(self, notification: NotificationData) -> Dict:
        """Build Slack message payload"""
        # Color mapping for severity
        color_map = {
            "info": "#36a64f",      # Green
            "warning": "#ff9500",   # Orange
            "error": "#ff0000",     # Red
            "critical": "#8b0000"   # Dark Red
        }
        
        # Emoji mapping for notification types
        emoji_map = {
            NotificationType.SCAN_STARTED: "🚀",
            NotificationType.SCAN_COMPLETED: "✅",
            NotificationType.VULNERABILITY_FOUND: "⚠️",
            NotificationType.HIGH_RISK_VULNERABILITY: "🚨",
            NotificationType.SCHEDULE_EXECUTED: "📅",
            NotificationType.SYSTEM_ERROR: "💥",
            NotificationType.DAILY_SUMMARY: "📊"
        }
        
        emoji = emoji_map.get(notification.type, "ℹ️")
        color = color_map.get(notification.severity, "#36a64f")
        timestamp = notification.timestamp or datetime.now()
        
        # Build attachment
        attachment = {
            "color": color,
            "title": f"{emoji} {notification.title}",
            "text": notification.message,
            "footer": "API Security Scanner",
            "ts": int(timestamp.timestamp())
        }
        
        # Add fields if data is provided
        if notification.data:
            fields = []
            for key, value in notification.data.items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, indent=2)[:100] + "..." if len(json.dumps(value)) > 100 else json.dumps(value)
                fields.append({
                    "title": key.replace("_", " ").title(),
                    "value": str(value),
                    "short": len(str(value)) < 50
                })
            attachment["fields"] = fields
        
        return {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [attachment]
        }
    
    def send_scan_started(self, service_name: str, endpoint_count: int, scan_type: str) -> bool:
        """Send scan started notification"""
        notification = NotificationData(
            type=NotificationType.SCAN_STARTED,
            title="Security Scan Started",
            message=f"Started {scan_type} scan for service: {service_name}",
            severity="info",
            data={
                "service": service_name,
                "endpoints": endpoint_count,
                "scan_type": scan_type,
                "start_time": datetime.now().isoformat()
            }
        )
        return self.send_notification(notification)
    
    def send_scan_completed(self, service_name: str, vulnerabilities_found: int, 
                          scan_duration: float, scan_type: str) -> bool:
        """Send scan completed notification"""
        severity = "warning" if vulnerabilities_found > 0 else "info"
        message = f"Completed {scan_type} scan for {service_name}"
        
        if vulnerabilities_found > 0:
            message += f" - Found {vulnerabilities_found} vulnerabilities!"
        else:
            message += " - No vulnerabilities found."
        
        notification = NotificationData(
            type=NotificationType.SCAN_COMPLETED,
            title="Security Scan Completed",
            message=message,
            severity=severity,
            data={
                "service": service_name,
                "vulnerabilities_found": vulnerabilities_found,
                "scan_duration": f"{scan_duration:.2f}s",
                "scan_type": scan_type,
                "completion_time": datetime.now().isoformat()
            }
        )
        return self.send_notification(notification)
    
    def send_vulnerability_alert(self, vulnerability: Dict) -> bool:
        """Send vulnerability alert"""
        severity = vulnerability.get('severity', 'medium')
        severity_level = "error" if severity in ['high', 'critical'] else "warning"
        
        notification = NotificationData(
            type=NotificationType.VULNERABILITY_FOUND,
            title=f"Vulnerability Found: {vulnerability.get('title', 'Unknown')}",
            message=f"Found {severity} severity vulnerability in {vulnerability.get('endpoint_path', 'Unknown endpoint')}",
            severity=severity_level,
            data={
                "vulnerability_type": vulnerability.get('type', 'Unknown'),
                "severity": severity,
                "endpoint": vulnerability.get('endpoint_path', 'Unknown'),
                "method": vulnerability.get('endpoint_method', 'Unknown'),
                "description": vulnerability.get('description', 'No description'),
                "tool": vulnerability.get('tool', 'Unknown'),
                "timestamp": datetime.now().isoformat()
            }
        )
        return self.send_notification(notification)
    
    def send_high_risk_alert(self, vulnerability: Dict) -> bool:
        """Send high-risk vulnerability alert"""
        notification = NotificationData(
            type=NotificationType.HIGH_RISK_VULNERABILITY,
            title="🚨 HIGH RISK VULNERABILITY DETECTED",
            message=f"Critical vulnerability found: {vulnerability.get('title', 'Unknown')}",
            severity="critical",
            data={
                "vulnerability_type": vulnerability.get('type', 'Unknown'),
                "severity": vulnerability.get('severity', 'critical'),
                "endpoint": vulnerability.get('endpoint_path', 'Unknown'),
                "method": vulnerability.get('endpoint_method', 'Unknown'),
                "description": vulnerability.get('description', 'No description'),
                "tool": vulnerability.get('tool', 'Unknown'),
                "recommendation": vulnerability.get('recommendation', 'Immediate action required'),
                "timestamp": datetime.now().isoformat()
            }
        )
        return self.send_notification(notification)
    
    def send_schedule_executed(self, schedule_name: str, service_name: str, 
                             scans_run: int, vulnerabilities_found: int) -> bool:
        """Send schedule execution notification"""
        severity = "warning" if vulnerabilities_found > 0 else "info"
        message = f"Scheduled scan '{schedule_name}' executed for {service_name}"
        
        if vulnerabilities_found > 0:
            message += f" - Found {vulnerabilities_found} vulnerabilities"
        else:
            message += " - No vulnerabilities found"
        
        notification = NotificationData(
            type=NotificationType.SCHEDULE_EXECUTED,
            title="Scheduled Scan Executed",
            message=message,
            severity=severity,
            data={
                "schedule_name": schedule_name,
                "service": service_name,
                "scans_run": scans_run,
                "vulnerabilities_found": vulnerabilities_found,
                "execution_time": datetime.now().isoformat()
            }
        )
        return self.send_notification(notification)
    
    def send_system_error(self, error_type: str, error_message: str, 
                         context: Optional[Dict] = None) -> bool:
        """Send system error notification"""
        notification = NotificationData(
            type=NotificationType.SYSTEM_ERROR,
            title=f"System Error: {error_type}",
            message=error_message,
            severity="error",
            data={
                "error_type": error_type,
                "error_message": error_message,
                "context": context or {},
                "timestamp": datetime.now().isoformat()
            }
        )
        return self.send_notification(notification)
    
    def send_daily_summary(self, summary_data: Dict) -> bool:
        """Send daily summary notification"""
        total_vulnerabilities = summary_data.get('total_vulnerabilities', 0)
        severity = "warning" if total_vulnerabilities > 0 else "info"
        
        notification = NotificationData(
            type=NotificationType.DAILY_SUMMARY,
            title="Daily Security Summary",
            message=f"Daily scan summary: {total_vulnerabilities} vulnerabilities found",
            severity=severity,
            data=summary_data
        )
        return self.send_notification(notification)
    
    def send_service_discovery_notification(self, services_found: int, sources: List[str]):
        """Send notification about service discovery results"""
        try:
            if not self.webhook_url:
                return
            
            # Build message
            sources_text = ', '.join(sources)
            color = 'good' if services_found > 0 else 'warning'
            
            payload = {
                'attachments': [{
                    'color': color,
                    'title': '🔍 Service Discovery Completed',
                    'text': f'Service discovery from {sources_text} has completed.',
                    'fields': [
                        {
                            'title': 'Services Found',
                            'value': str(services_found),
                            'short': True
                        },
                        {
                            'title': 'Sources',
                            'value': sources_text,
                            'short': True
                        },
                        {
                            'title': 'Timestamp',
                            'value': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                            'short': True
                        }
                    ],
                    'footer': 'API Security Scanner',
                    'ts': int(time.time())
                }]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"✅ Service discovery notification sent: {services_found} services found")
            
        except Exception as e:
            logger.error(f"❌ Failed to send service discovery notification: {e}")
    
    def send_auto_scan_notification(self, service_name: str, endpoint_count: int, 
                                   change_type: str, severity: str) -> bool:
        """Send notification about auto-scanning triggered by API changes"""
        try:
            if not self.webhook_url:
                return False
            
            # Determine color based on severity
            color_map = {
                'low': 'good',
                'medium': 'warning', 
                'high': 'danger'
            }
            color = color_map.get(severity, 'warning')
            
            # Build message
            payload = {
                'attachments': [{
                    'color': color,
                    'title': '🚨 Auto-Scan Triggered by API Changes',
                    'text': f'API changes detected in service: **{service_name}**',
                    'fields': [
                        {
                            'title': 'Service Name',
                            'value': service_name,
                            'short': True
                        },
                        {
                            'title': 'Endpoints to Scan',
                            'value': str(endpoint_count),
                            'short': True
                        },
                        {
                            'title': 'Change Type',
                            'value': change_type.replace('_', ' ').title(),
                            'short': True
                        },
                        {
                            'title': 'Severity',
                            'value': severity.title(),
                            'short': True
                        },
                        {
                            'title': 'Action',
                            'value': 'Automatically triggered comprehensive security scan',
                            'short': False
                        },
                        {
                            'title': 'Timestamp',
                            'value': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                            'short': True
                        }
                    ],
                    'footer': 'API Security Scanner - Real-Time Monitoring',
                    'ts': int(time.time())
                }]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"✅ Auto-scan notification sent for service: {service_name}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send auto-scan notification: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test Slack connection"""
        if not self.enabled:
            return False
        
        test_notification = NotificationData(
            type=NotificationType.SCAN_STARTED,
            title="Slack Integration Test",
            message="This is a test notification to verify Slack integration",
            severity="info",
            data={
                "test": True,
                "timestamp": datetime.now().isoformat()
            }
        )
        
        return self.send_notification(test_notification)

# Global instance
slack_notifier = SlackNotifier()
