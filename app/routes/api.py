"""
API routes for programmatic access to the security scanner
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required
from app import db
from app.models import Service, ApiVersion, Endpoint, Scan, Vulnerability, ScanTarget
from app.tasks import scan_endpoint, crawl_and_update_services
# from app.utils.slack_client import SlackNotifier  # Removed slack integration
from datetime import datetime, timedelta, timezone
import json

api_bp = Blueprint('api', __name__)

@api_bp.route('/services', methods=['GET'])
@login_required
def get_services():
    """Get all services"""
    try:
        services = Service.query.all()
        return jsonify({
            'services': [
                {
                    'id': service.id,
                    'name': service.name,
                    'api_url': service.api_url,
                    'status': service.status,
                    'last_checked': service.last_checked.isoformat() if service.last_checked else None,
                    'created_at': service.created_at.isoformat(),
                    'updated_at': service.updated_at.isoformat()
                }
                for service in services
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/services/<service_id>', methods=['GET'])
@login_required
def get_service(service_id):
    """Get a specific service"""
    try:
        service = Service.query.get_or_404(service_id)
        return jsonify({
            'id': service.id,
            'name': service.name,
            'api_url': service.api_url,
            'status': service.status,
            'last_checked': service.last_checked.isoformat() if service.last_checked else None,
            'created_at': service.created_at.isoformat(),
            'updated_at': service.updated_at.isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/services/<service_id>/endpoints', methods=['GET'])
@login_required
def get_service_endpoints(service_id):
    """Get endpoints for a specific service"""
    try:
        service = Service.query.get_or_404(service_id)
        endpoints = Endpoint.query.filter_by(service_id=service_id).all()
        
        return jsonify({
            'service': {
                'id': service.id,
                'name': service.name
            },
            'endpoints': [
                {
                    'id': endpoint.id,
                    'path': endpoint.path,
                    'method': endpoint.method,
                    'operation_id': endpoint.operation_id,
                    'summary': endpoint.summary,
                    'risk_score': endpoint.risk_score,
                    'created_at': endpoint.created_at.isoformat(),
                    'updated_at': endpoint.updated_at.isoformat()
                }
                for endpoint in endpoints
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/endpoints', methods=['GET'])
@login_required
def get_endpoints():
    """Get all endpoints with pagination"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        service_id = request.args.get('service_id')
        method = request.args.get('method')
        
        query = Endpoint.query
        
        if service_id:
            query = query.filter_by(service_id=service_id)
        
        if method:
            query = query.filter_by(method=method.upper())
        
        endpoints = query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'endpoints': [
                {
                    'id': endpoint.id,
                    'path': endpoint.path,
                    'method': endpoint.method,
                    'operation_id': endpoint.operation_id,
                    'summary': endpoint.summary,
                    'service_name': endpoint.service.name,
                    'risk_score': endpoint.risk_score,
                    'created_at': endpoint.created_at.isoformat()
                }
                for endpoint in endpoints.items
            ],
            'pagination': {
                'page': endpoints.page,
                'pages': endpoints.pages,
                'per_page': endpoints.per_page,
                'total': endpoints.total,
                'has_next': endpoints.has_next,
                'has_prev': endpoints.has_prev
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/endpoints/<endpoint_id>', methods=['GET'])
@login_required
def get_endpoint(endpoint_id):
    """Get a specific endpoint"""
    try:
        endpoint = Endpoint.query.get_or_404(endpoint_id)
        
        return jsonify({
            'id': endpoint.id,
            'path': endpoint.path,
            'method': endpoint.method,
            'operation_id': endpoint.operation_id,
            'summary': endpoint.summary,
            'description': endpoint.description,
            'parameters_schema': endpoint.parameters_schema,
            'request_body_schema': endpoint.request_body_schema,
            'response_schema': endpoint.response_schema,
            'param_values': endpoint.param_values,
            'risk_score': endpoint.risk_score,
            'service': {
                'id': endpoint.service.id,
                'name': endpoint.service.name
            },
            'created_at': endpoint.created_at.isoformat(),
            'updated_at': endpoint.updated_at.isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/endpoints/<endpoint_id>/scan', methods=['POST'])
@login_required
def trigger_endpoint_scan(endpoint_id):
    """Trigger a scan for an endpoint"""
    try:
        endpoint = Endpoint.query.get_or_404(endpoint_id)
        data = request.get_json() or {}
        scan_type = data.get('scan_type', 'combined')
        
        # Create scan record first
        scan = Scan(
            endpoint_id=endpoint_id,
            scan_type=scan_type,
            status='pending',
            scan_time=datetime.now(timezone.utc),
            scan_config=json.dumps({
                'scan_depth': 'standard',
                'timeout': 30,
                'tools': ['zap', 'nuclei', 'sqlmap'],
                'notifications': True,
                'save_parameters': True
            })
        )
        
        db.session.add(scan)
        db.session.commit()
        
        # Queue scan task with the scan ID and scan config
        task = scan_endpoint.delay(scan.id, scan.scan_config)
        
        return jsonify({
            'status': 'success',
            'message': f'Scan queued for endpoint {endpoint.path}',
            'task_id': task.id,
            'scan_id': scan.id,
            'endpoint': {
                'id': endpoint.id,
                'path': endpoint.path,
                'method': endpoint.method
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/scans', methods=['GET'])
@login_required
def get_scans():
    """Get all scans with pagination"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status = request.args.get('status')
        endpoint_id = request.args.get('endpoint_id')
        
        query = Scan.query
        
        if status:
            query = query.filter_by(status=status)
        
        if endpoint_id:
            query = query.filter_by(endpoint_id=endpoint_id)
        
        scans = query.order_by(Scan.scan_time.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'scans': [
                {
                    'id': scan.id,
                    'scan_type': scan.scan_type,
                    'status': scan.status,
                    'scan_time': scan.scan_time.isoformat(),
                    'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                    'duration': scan.duration,
                    'endpoint': {
                        'id': scan.endpoint.id,
                        'path': scan.endpoint.path,
                        'method': scan.endpoint.method,
                        'service_name': scan.endpoint.service.name
                    }
                }
                for scan in scans.items
            ],
            'pagination': {
                'page': scans.page,
                'pages': scans.pages,
                'per_page': scans.per_page,
                'total': scans.total,
                'has_next': scans.has_next,
                'has_prev': scans.has_prev
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/scans/<scan_id>', methods=['GET'])
@login_required
def get_scan(scan_id):
    """Get a specific scan"""
    try:
        scan = Scan.query.get_or_404(scan_id)
        vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
        
        return jsonify({
            'id': scan.id,
            'scan_type': scan.scan_type,
            'status': scan.status,
            'scan_time': scan.scan_time.isoformat(),
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'duration': scan.duration,
            'param_values_used': scan.param_values_used,
            'tools_used': scan.tools_used,
            'endpoint': {
                'id': scan.endpoint.id,
                'path': scan.endpoint.path,
                'method': scan.endpoint.method,
                'service_name': scan.endpoint.service.name
            },
            'vulnerabilities': [
                {
                    'id': vuln.id,
                    'name': vuln.name,
                    'description': vuln.description,
                    'severity': vuln.severity,
                    'category': vuln.category,
                    'evidence': vuln.evidence,
                    'false_positive': vuln.false_positive,
                    'remediated': vuln.remediated,
                    'created_at': vuln.created_at.isoformat()
                }
                for vuln in vulnerabilities
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/vulnerabilities', methods=['GET'])
@login_required
def get_vulnerabilities():
    """Get all vulnerabilities with pagination"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        severity = request.args.get('severity')
        category = request.args.get('category')
        false_positive = request.args.get('false_positive')
        remediated = request.args.get('remediated')
        
        query = Vulnerability.query
        
        if severity:
            query = query.filter_by(severity=severity)
        
        if category:
            query = query.filter_by(category=category)
        
        if false_positive is not None:
            query = query.filter_by(false_positive=bool(false_positive))
        
        if remediated is not None:
            query = query.filter_by(remediated=bool(remediated))
        
        vulnerabilities = query.order_by(Vulnerability.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'vulnerabilities': [
                {
                    'id': vuln.id,
                    'name': vuln.name,
                    'description': vuln.description,
                    'severity': vuln.severity,
                    'category': vuln.category,
                    'evidence': vuln.evidence,
                    'false_positive': vuln.false_positive,
                    'remediated': vuln.remediated,
                    'scan': {
                        'id': vuln.scan.id,
                        'scan_type': vuln.scan.scan_type,
                        'scan_time': vuln.scan.scan_time.isoformat()
                    },
                    'endpoint': {
                        'id': vuln.scan.endpoint.id,
                        'path': vuln.scan.endpoint.path,
                        'method': vuln.scan.endpoint.method,
                        'service_name': vuln.scan.endpoint.service.name
                    },
                    'created_at': vuln.created_at.isoformat()
                }
                for vuln in vulnerabilities.items
            ],
            'pagination': {
                'page': vulnerabilities.page,
                'pages': vulnerabilities.pages,
                'per_page': vulnerabilities.per_page,
                'total': vulnerabilities.total,
                'has_next': vulnerabilities.has_next,
                'has_prev': vulnerabilities.has_prev
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/vulnerabilities/<vulnerability_id>', methods=['GET'])
@login_required
def get_vulnerability(vulnerability_id):
    """Get a specific vulnerability"""
    try:
        vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
        
        return jsonify({
            'id': vulnerability.id,
            'name': vulnerability.name,
            'description': vulnerability.description,
            'severity': vulnerability.severity,
            'cvss_score': vulnerability.cvss_score,
            'risk_score': vulnerability.risk_score,
            'category': vulnerability.category,
            'evidence': vulnerability.evidence,
            'details': vulnerability.details,
            'false_positive': vulnerability.false_positive,
            'remediated': vulnerability.remediated,
            'remediated_at': vulnerability.remediated_at.isoformat() if vulnerability.remediated_at else None,
            'scan': {
                'id': vulnerability.scan.id,
                'scan_type': vulnerability.scan.scan_type,
                'scan_time': vulnerability.scan.scan_time.isoformat()
            },
            'endpoint': {
                'id': vulnerability.scan.endpoint.id,
                'path': vulnerability.scan.endpoint.path,
                'method': vulnerability.scan.endpoint.method,
                'service_name': vulnerability.scan.endpoint.service.name
            },
            'created_at': vulnerability.created_at.isoformat(),
            'updated_at': vulnerability.updated_at.isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/vulnerabilities/<vulnerability_id>/mark-false-positive', methods=['POST'])
@login_required
def mark_vulnerability_false_positive(vulnerability_id):
    """Mark a vulnerability as false positive"""
    try:
        vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
        vulnerability.false_positive = True
        vulnerability.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Vulnerability marked as false positive'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/vulnerabilities/<vulnerability_id>/mark-remediated', methods=['POST'])
@login_required
def mark_vulnerability_remediated(vulnerability_id):
    """Mark a vulnerability as remediated"""
    try:
        vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
        vulnerability.remediated = True
        vulnerability.remediated_at = datetime.now(timezone.utc)
        vulnerability.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Vulnerability marked as remediated'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/discover-services', methods=['POST'])
@login_required
def trigger_service_discovery():
    """Trigger service discovery"""
    try:
        task = crawl_and_update_services.delay()
        
        return jsonify({
            'status': 'success',
            'message': 'Service discovery queued',
            'task_id': task.id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/statistics', methods=['GET'])
@login_required
def get_statistics():
    """Get dashboard statistics"""
    try:
        # Basic counts
        total_services = Service.query.count()
        total_endpoints = Endpoint.query.count()
        total_scans = Scan.query.count()
        total_vulnerabilities = Vulnerability.query.count()
        
        # Vulnerability counts by severity
        severity_counts = db.session.query(
            Vulnerability.severity,
            db.func.count(Vulnerability.id).label('count')
        ).group_by(Vulnerability.severity).all()
        
        # Scan status counts
        scan_status_counts = db.session.query(
            Scan.status,
            db.func.count(Scan.id).label('count')
        ).group_by(Scan.status).all()
        
        # Recent activity
        recent_scans = Scan.query.order_by(Scan.scan_time.desc()).limit(5).all()
        recent_vulnerabilities = Vulnerability.query.order_by(
            Vulnerability.created_at.desc()
        ).limit(5).all()
        
        return jsonify({
            'total_services': total_services,
            'total_endpoints': total_endpoints,
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'severity_counts': {
                item.severity: item.count for item in severity_counts
            },
            'scan_status_counts': {
                item.status: item.count for item in scan_status_counts
            },
            'recent_scans': [
                {
                    'id': scan.id,
                    'endpoint': scan.endpoint.path,
                    'status': scan.status,
                    'scan_time': scan.scan_time.isoformat()
                }
                for scan in recent_scans
            ],
            'recent_vulnerabilities': [
                {
                    'id': vuln.id,
                    'name': vuln.name,
                    'severity': vuln.severity,
                    'created_at': vuln.created_at.isoformat()
                }
                for vuln in recent_vulnerabilities
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# @api_bp.route('/test-slack', methods=['POST'])
# @login_required
# def test_slack_integration():
#     """Test Slack integration"""
#     try:
#         # notifier = SlackNotifier()  # Removed slack integration
#         # success = notifier.send_test_message()
#         
#         # if success:
#         #     return jsonify({
#         #         'status': 'success',
#         #         'message': 'Slack test message sent successfully'
#         #     })
#         # else:
#         #     return jsonify({
#         #         'status': 'error',
#         #         'message': 'Failed to send Slack test message'
#         #     })
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

