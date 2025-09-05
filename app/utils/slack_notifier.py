#!/usr/bin/env python3
"""
Enhanced Slack Notification System for API Security Scanner
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
import hashlib

logger = logging.getLogger(__name__)

class NotificationType(Enum):
    """Types of notifications"""
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    VULNERABILITY_FOUND = "vulnerability_found"
    HIGH_RISK_VULNERABILITY = "high_risk_vulnerability"
    SYSTEM_ERROR = "system_error"

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
    """Enhanced Slack notification system with color-coded messages and dashboard links"""
    
    def __init__(self):
        self.webhook_url = os.getenv('SLACK_WEBHOOK_URL')
        self.channel = os.getenv('SLACK_CHANNEL', '#api-security')
        self.username = os.getenv('SLACK_USERNAME', 'API Security Scanner')
        self.icon_emoji = os.getenv('SLACK_ICON_EMOJI', ':shield:')
        self.dashboard_url = os.getenv('DASHBOARD_URL', 'http://localhost:5001')
        self.enabled = bool(self.webhook_url)
        
        # Deduplication cache to prevent duplicate vulnerability notifications
        self._notification_cache = {}
        self._cache_ttl = 300  # 5 minutes TTL for deduplication
        
        if not self.enabled:
            logger.warning("⚠️  Slack notifications disabled - SLACK_WEBHOOK_URL not configured")
        else:
            logger.info("✅ Slack notifications enabled")
    
    def _generate_vulnerability_hash(self, vulnerability: Dict) -> str:
        """Generate a hash for vulnerability deduplication"""
        # Create a hash based on vulnerability name, endpoint, and severity
        # This helps identify duplicate vulnerabilities across different scans
        hash_data = f"{vulnerability.get('name', '')}-{vulnerability.get('endpoint_path', '')}-{vulnerability.get('endpoint_method', '')}-{vulnerability.get('severity', '')}"
        return hashlib.md5(hash_data.encode()).hexdigest()
    
    def _is_duplicate_vulnerability(self, vulnerability: Dict) -> bool:
        """Check if this vulnerability notification was recently sent"""
        vuln_hash = self._generate_vulnerability_hash(vulnerability)
        current_time = time.time()
        
        # Clean expired entries
        expired_keys = [k for k, v in self._notification_cache.items() if current_time - v > self._cache_ttl]
        for key in expired_keys:
            del self._notification_cache[key]
        
        # Check if this vulnerability was recently notified
        if vuln_hash in self._notification_cache:
            logger.debug(f"🔄 Duplicate vulnerability notification suppressed: {vulnerability.get('name', 'Unknown')}")
            return True
        
        # Add to cache
        self._notification_cache[vuln_hash] = current_time
        return False
    
    def clear_notification_cache(self):
        """Clear the notification deduplication cache"""
        self._notification_cache.clear()
        logger.info("🧹 Notification deduplication cache cleared")
    
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
        """Build Slack message payload with enhanced formatting"""
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
            NotificationType.SYSTEM_ERROR: "💥"
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
    
    def send_scan_started(self, scan_data: Dict) -> bool:
        """Send detailed scan started notification"""
        try:
            if not self.webhook_url:
                return False
            
            scan_type = scan_data.get('scan_type', 'unknown')
            service_name = scan_data.get('service_name', 'Unknown Service')
            endpoint_path = scan_data.get('endpoint_path', 'Unknown Endpoint')
            endpoint_method = scan_data.get('endpoint_method', 'Unknown')
            tools_used = scan_data.get('tools_used', [])
            scan_id = scan_data.get('scan_id', 'Unknown')
            
            # Determine if it's endpoint or service scan
            is_service_scan = scan_data.get('is_service_scan', False)
            endpoint_count = scan_data.get('endpoint_count', 1)
            
            # Build title and message
            if is_service_scan:
                title = f"🚀 {scan_type.title()} Scan Started - Service"
                message = f"Starting comprehensive security scan for service: **{service_name}**"
                scan_scope = f"Scanning {endpoint_count} endpoints in service"
            else:
                title = f"🚀 {scan_type.title()} Scan Started - Endpoint"
                message = f"Starting security scan for endpoint: **{endpoint_method} {endpoint_path}**"
                scan_scope = f"Single endpoint scan"
            
            # Build fields
            fields = [
                {
                    "title": "Service",
                    "value": service_name,
                    "short": True
                },
                {
                    "title": "Scan Type",
                    "value": scan_type.title(),
                    "short": True
                },
                {
                    "title": "Scope",
                    "value": scan_scope,
                    "short": True
                },
                {
                    "title": "Security Tools",
                    "value": ", ".join(tools_used) if tools_used else "ZAP, Nuclei, SQLMap",
                    "short": True
                }
            ]
            
            # Add endpoint details for single endpoint scans
            if not is_service_scan:
                fields.extend([
                    {
                        "title": "Endpoint",
                        "value": f"{endpoint_method} {endpoint_path}",
                        "short": False
                    }
                ])
            
            # Add scan ID and timestamp
            fields.extend([
                {
                    "title": "Scan ID",
                    "value": scan_id[:8] + "..." if len(scan_id) > 8 else scan_id,
                    "short": True
                },
                {
                    "title": "Started At",
                    "value": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "short": True
                }
            ])
            
            # Add dashboard link
            if is_service_scan:
                dashboard_link = f"{self.dashboard_url}/services"
                link_text = "View Service Details"
            else:
                dashboard_link = f"{self.dashboard_url}/scans/{scan_id}"
                link_text = "View Scan Details"
            
            fields.append({
                "title": "Dashboard",
                "value": f"<{dashboard_link}|{link_text}>",
                "short": False
            })
            
            # Build payload
            payload = {
                'attachments': [{
                    'color': '#36a64f',  # Green for started
                    'title': title,
                    'text': message,
                    'fields': fields,
                    'footer': 'API Security Scanner - Scan Started',
                    'ts': int(time.time())
                }]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"✅ Scan started notification sent for {scan_type} scan")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send scan started notification: {e}")
            return False
    
    def send_scan_completed(self, scan_data: Dict) -> bool:
        """Send detailed scan completed notification with vulnerability details"""
        try:
            if not self.webhook_url:
                return False
            
            scan_type = scan_data.get('scan_type', 'unknown')
            service_name = scan_data.get('service_name', 'Unknown Service')
            endpoint_path = scan_data.get('endpoint_path', 'Unknown Endpoint')
            endpoint_method = scan_data.get('endpoint_method', 'Unknown')
            scan_id = scan_data.get('scan_id', 'Unknown')
            duration = scan_data.get('duration', 0)
            tools_used = scan_data.get('tools_used', [])
            vulnerabilities = scan_data.get('vulnerabilities', [])
            is_service_scan = scan_data.get('is_service_scan', False)
            
            # Count vulnerabilities by severity
            vuln_counts = {'high': 0, 'medium': 0, 'low': 0, 'critical': 0}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low').lower()
                vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
            
            total_vulns = len(vulnerabilities)
            
            # Determine color and emoji based on vulnerabilities
            if vuln_counts['critical'] > 0:
                color = '#8b0000'  # Dark red
                emoji = '🚨'
                severity_text = 'CRITICAL VULNERABILITIES FOUND!'
            elif vuln_counts['high'] > 0:
                color = '#ff0000'  # Red
                emoji = '⚠️'
                severity_text = f'Found {total_vulns} vulnerabilities'
            elif total_vulns > 0:
                color = '#ff9500'  # Orange
                emoji = '⚠️'
                severity_text = f'Found {total_vulns} vulnerabilities'
            else:
                color = '#36a64f'  # Green
                emoji = '✅'
                severity_text = 'No vulnerabilities found'
            
            # Build title and message
            if is_service_scan:
                title = f"{emoji} {scan_type.title()} Scan Completed - Service"
                message = f"Security scan completed for service: **{service_name}** - {severity_text}"
            else:
                title = f"{emoji} {scan_type.title()} Scan Completed - Endpoint"
                message = f"Security scan completed for endpoint: **{endpoint_method} {endpoint_path}** - {severity_text}"
            
            # Build fields
            fields = [
                {
                    "title": "Service",
                    "value": service_name,
                    "short": True
                },
                {
                    "title": "Scan Type",
                    "value": scan_type.title(),
                    "short": True
                },
                {
                    "title": "Duration",
                    "value": f"{duration:.2f}s",
                    "short": True
                },
                {
                    "title": "Tools Used",
                    "value": ", ".join(tools_used) if tools_used else "ZAP, Nuclei, SQLMap",
                    "short": True
                }
            ]
            
            # Add endpoint details for single endpoint scans
            if not is_service_scan:
                fields.append({
                    "title": "Endpoint",
                    "value": f"{endpoint_method} {endpoint_path}",
                    "short": False
                })
            
            # Add vulnerability summary
            if total_vulns > 0:
                vuln_summary = []
                for severity, count in vuln_counts.items():
                    if count > 0:
                        vuln_summary.append(f"{severity.title()}: {count}")
                
                fields.append({
                    "title": "Vulnerability Summary",
                    "value": " | ".join(vuln_summary),
                    "short": False
                })
                
                # Add top vulnerabilities (max 3)
                top_vulns = sorted(vulnerabilities, key=lambda x: {
                    'critical': 4, 'high': 3, 'medium': 2, 'low': 1
                }.get(x.get('severity', 'low').lower(), 1), reverse=True)[:3]
                
                vuln_details = []
                for vuln in top_vulns:
                    name = vuln.get('name', 'Unknown')[:50]
                    severity = vuln.get('severity', 'unknown').upper()
                    vuln_details.append(f"• {severity}: {name}")
                
                if vuln_details:
                    fields.append({
                        "title": "Top Vulnerabilities",
                        "value": "\n".join(vuln_details),
                        "short": False
                    })
            else:
                fields.append({
                    "title": "Security Status",
                    "value": "✅ All security checks passed",
                    "short": False
                })
            
            # Add scan ID and timestamp
            fields.extend([
                {
                    "title": "Scan ID",
                    "value": scan_id[:8] + "..." if len(scan_id) > 8 else scan_id,
                    "short": True
                },
                {
                    "title": "Completed At",
                    "value": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "short": True
                }
            ])
            
            # Add dashboard link
            if is_service_scan:
                dashboard_link = f"{self.dashboard_url}/services"
                link_text = "View Service Details"
            else:
                dashboard_link = f"{self.dashboard_url}/scans/{scan_id}"
                link_text = "View Scan Details"
            
            fields.append({
                "title": "Dashboard",
                "value": f"<{dashboard_link}|{link_text}>",
                "short": False
            })
            
            # Build payload
            payload = {
                'attachments': [{
                    'color': color,
                    'title': title,
                    'text': message,
                    'fields': fields,
                    'footer': 'API Security Scanner - Scan Completed',
                    'ts': int(time.time())
                }]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"✅ Scan completed notification sent for {scan_type} scan")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send scan completed notification: {e}")
            return False
    
    def send_vulnerability_alert(self, vulnerability: Dict) -> bool:
        """Send detailed vulnerability alert"""
        try:
            if not self.webhook_url:
                return False
            
            # Check for duplicate vulnerability notifications
            if self._is_duplicate_vulnerability(vulnerability):
                return True  # Return True to indicate "handled" but don't send duplicate
            
            severity = vulnerability.get('severity', 'medium').lower()
            name = vulnerability.get('name', 'Unknown Vulnerability')
            description = vulnerability.get('description', 'No description available')
            endpoint_path = vulnerability.get('endpoint_path', 'Unknown')
            endpoint_method = vulnerability.get('endpoint_method', 'Unknown')
            tool_used = vulnerability.get('tool', 'Unknown')
            cvss_score = vulnerability.get('cvss_score', 'N/A')
            category = vulnerability.get('category', 'Unknown')
            scan_id = vulnerability.get('scan_id', 'Unknown')
            
            # Determine color and emoji based on severity
            color_map = {
                'critical': '#8b0000',  # Dark red
                'high': '#ff0000',      # Red
                'medium': '#ff9500',    # Orange
                'low': '#ffcc00'        # Yellow
            }
            
            emoji_map = {
                'critical': '🚨',
                'high': '⚠️',
                'medium': '⚠️',
                'low': 'ℹ️'
            }
            
            color = color_map.get(severity, '#ff9500')
            emoji = emoji_map.get(severity, '⚠️')
            
            # Build title and message
            title = f"{emoji} {severity.upper()} Risk Vulnerability Found"
            
            # Format endpoint information properly
            if endpoint_path != 'Unknown' and endpoint_method != 'Unknown':
                endpoint_info = f"{endpoint_method} {endpoint_path}"
            elif endpoint_path != 'Unknown':
                endpoint_info = endpoint_path
            elif endpoint_method != 'Unknown':
                endpoint_info = endpoint_method
            else:
                endpoint_info = "Unknown endpoint"
            
            message = f"**{name}** detected in {endpoint_info}"
            
            # Build fields
            fields = [
                {
                    "title": "Vulnerability",
                    "value": name,
                    "short": False
                },
                {
                    "title": "Severity",
                    "value": severity.upper(),
                    "short": True
                },
                {
                    "title": "Category",
                    "value": category,
                    "short": True
                },
                {
                    "title": "CVSS Score",
                    "value": str(cvss_score) if cvss_score != 'N/A' else 'N/A',
                    "short": True
                },
                {
                    "title": "Endpoint",
                    "value": endpoint_info,
                    "short": False
                },
                {
                    "title": "Detection Tool",
                    "value": tool_used,
                    "short": True
                },
                {
                    "title": "Scan ID",
                    "value": scan_id[:8] + "..." if len(scan_id) > 8 else scan_id,
                    "short": True
                },
                {
                    "title": "Detected At",
                    "value": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "short": True
                }
            ]
            
            # Add description if available
            if description and len(description) > 0:
                # Truncate description if too long
                desc_text = description[:200] + "..." if len(description) > 200 else description
                fields.append({
                    "title": "Description",
                    "value": desc_text,
                    "short": False
                })
            
            # Add dashboard link
            dashboard_link = f"{self.dashboard_url}/vulnerabilities"
            fields.append({
                "title": "Dashboard",
                "value": f"<{dashboard_link}|View All Vulnerabilities>",
                "short": False
            })
            
            # Build payload
            payload = {
                'attachments': [{
                    'color': color,
                    'title': title,
                    'text': message,
                    'fields': fields,
                    'footer': 'API Security Scanner - Vulnerability Alert',
                    'ts': int(time.time())
                }]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"✅ Vulnerability alert sent: {name}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send vulnerability alert: {e}")
            return False
    
    def send_system_error(self, error_type: str, error_message: str, 
                         context: Optional[Dict] = None) -> bool:
        """Send system error notification"""
        try:
            if not self.webhook_url:
                return False
            
            # Build title and message
            title = f"💥 System Error: {error_type}"
            message = f"**{error_message}**"
            
            # Build fields
            fields = [
                {
                    "title": "Error Type",
                    "value": error_type,
                    "short": True
                },
                {
                    "title": "Error Message",
                    "value": error_message,
                    "short": False
                },
                {
                    "title": "Timestamp",
                    "value": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "short": True
                }
            ]
            
            # Add context if available
            if context:
                for key, value in context.items():
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, indent=2)[:100] + "..." if len(json.dumps(value)) > 100 else json.dumps(value)
                    fields.append({
                        "title": key.replace("_", " ").title(),
                        "value": str(value),
                        "short": len(str(value)) < 50
                    })
            
            # Add dashboard link
            dashboard_link = f"{self.dashboard_url}/dashboard"
            fields.append({
                "title": "Dashboard",
                "value": f"<{dashboard_link}|View Dashboard>",
                "short": False
            })
            
            # Build payload
            payload = {
                'attachments': [{
                    'color': '#ff0000',  # Red for errors
                    'title': title,
                    'text': message,
                    'fields': fields,
                    'footer': 'API Security Scanner - System Error',
                    'ts': int(time.time())
                }]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"✅ System error notification sent: {error_type}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send system error notification: {e}")
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