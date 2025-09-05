"""
Flask dashboard routes for the web interface
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user, login_user, logout_user
from app import db
from app.models import Service, ApiVersion, Endpoint, Scan, Vulnerability, ScanTarget
from app.tasks import scan_endpoint, crawl_and_update_services
from app.utils.slack_notifier import slack_notifier, NotificationData, NotificationType
from app.utils.ai_description_generator import AIDescriptionGenerator
from app.utils.scan_scheduler import ScanScheduler
from datetime import datetime, timedelta, timezone
import json
import logging

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        from app.auth import authenticate_user
        user = authenticate_user(username, password)
        
        if user:
            login_user(user)
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('dashboard/login.html')

@dashboard_bp.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    return redirect(url_for('dashboard.login'))

@dashboard_bp.route('/discover-services')
@login_required
def discover_services():
    """Discover services from the API portal"""
    try:
        from app.utils.crawler import crawl_and_update
        result = crawl_and_update()
        
        if result:
            flash('Services discovered successfully!', 'success')
        else:
            flash('No new services found or error occurred.', 'info')
            
    except Exception as e:
        flash(f'Error discovering services: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.services'))

@dashboard_bp.route('/')
@login_required
def index():
    """Dashboard home page"""
    # Get summary statistics
    total_services = Service.query.count()
    total_endpoints = Endpoint.query.count()
    
    # Count unique scans (not multiple tools as separate scans)
    total_scans = db.session.query(db.func.count(db.distinct(Scan.id))).scalar()
    
    # Count unique vulnerabilities (not duplicates)
    total_vulnerabilities = db.session.query(db.func.count(db.distinct(Vulnerability.id))).scalar()
    
    # Get recent scans with proper joins - handle missing relationships
    try:
        recent_scans = Scan.query.join(Endpoint).join(Service).order_by(
            Scan.scan_time.desc()
        ).limit(10).all()
    except Exception:
        # Fallback to scans without joins if relationships are missing
        recent_scans = Scan.query.order_by(Scan.scan_time.desc()).limit(10).all()
    
    # Get recent vulnerabilities with proper joins - handle missing relationships
    try:
        recent_vulnerabilities = Vulnerability.query.join(Scan).join(Endpoint).join(Service).order_by(
            Vulnerability.created_at.desc()
        ).limit(10).all()
    except Exception:
        # Fallback to vulnerabilities without joins if relationships are missing
        recent_vulnerabilities = Vulnerability.query.join(Scan).order_by(
            Vulnerability.created_at.desc()
        ).limit(10).all()
    
    # Get services with most vulnerabilities
    try:
        services_with_vulns = db.session.query(
            Service.id,
            Service.name,
            db.func.count(Vulnerability.id).label('vuln_count')
        ).join(Endpoint).join(Scan).join(Vulnerability).group_by(
            Service.id, Service.name
        ).order_by(db.func.count(Vulnerability.id).desc()).limit(5).all()
    except Exception:
        # Fallback to empty list if relationships are missing
        services_with_vulns = []
    
    # Get all services for scan modal dropdown
    all_services = Service.query.order_by(Service.name).all()
    
    # Create stats object for template
    stats = {
        'services': total_services,
        'endpoints': total_endpoints,
        'scans': total_scans,
        'vulnerabilities': total_vulnerabilities
    }
    
    return render_template('dashboard/index.html',
                         stats=stats,
                         recent_scans=recent_scans,
                         recent_vulnerabilities=recent_vulnerabilities,
                         services_with_vulns=services_with_vulns,
                         all_services=all_services)

@dashboard_bp.route('/services')
@login_required
def services():
    """Services list page"""
    services = Service.query.order_by(Service.name).all()
    
    # Get discovery settings for status indicator
    from app.utils.discovery_manager import get_discovery_settings
    discovery_settings = get_discovery_settings()
    
    # Get last discovery stats from the settings
    discovery_stats = {
        'last_run': discovery_settings.get('last_run'),
        'services_discovered': discovery_settings.get('last_count', 0),
        'status': discovery_settings.get('last_status', 'Unknown')
    }
    
    return render_template('dashboard/services.html', 
                         services=services,
                         discovery_settings=discovery_settings,
                         discovery_stats=discovery_stats)



@dashboard_bp.route('/generate-service-description/<service_id>', methods=['POST'])
@login_required
def generate_service_description(service_id):
    """Generate AI-powered description for a service"""
    try:
        service = Service.query.get_or_404(service_id)
        
        # Get service endpoints
        endpoints = Endpoint.query.filter_by(service_id=service.id).all()
        
        # Create AI description generator
        ai_generator = AIDescriptionGenerator()
        
        # Generate description
        service_data = {
            'name': service.name,
            'api_url': service.api_url,
            'endpoints': [{
                'method': e.method,
                'path': e.path,
                'summary': e.summary
            } for e in endpoints]
        }
        
        result = ai_generator.generate_service_description(service_data)
        
        return jsonify({
            'success': True,
            'description': result['description'],
            'endpoint_count': result['endpoint_count'],
            'methods_used': result['methods_used'],
            'source': result['source']
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/schedules')
@login_required
def schedules():
    """Scan schedules page"""
    scheduler = ScanScheduler()
    schedules = scheduler.get_schedules()
    stats = scheduler.get_schedule_stats()
    services = Service.query.all()
    
    return render_template('dashboard/schedules.html', 
                         schedules=schedules, 
                         stats=stats,
                         services=services)

@dashboard_bp.route('/schedules/create', methods=['POST'])
@login_required
def create_schedule():
    """Create a new scan schedule"""
    try:
        service_id = request.form.get('service_id')
        name = request.form.get('name')
        cron_expression = request.form.get('cron_expression')
        scan_type = request.form.get('scan_type', 'combined')
        
        if not all([service_id, name, cron_expression]):
            flash('All fields are required', 'error')
            return redirect(url_for('dashboard.schedules'))
        
        scheduler = ScanScheduler()
        schedule_id = scheduler.create_schedule(service_id, name, cron_expression, scan_type)
        
        flash(f'Scan schedule "{name}" created successfully!', 'success')
        
    except Exception as e:
        flash(f'Error creating schedule: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.schedules'))

@dashboard_bp.route('/schedules/<schedule_id>/update', methods=['POST'])
@login_required
def update_schedule(schedule_id):
    """Update a scan schedule"""
    try:
        name = request.form.get('name')
        cron_expression = request.form.get('cron_expression')
        scan_type = request.form.get('scan_type')
        is_active = request.form.get('is_active') == 'on'
        
        scheduler = ScanScheduler()
        success = scheduler.update_schedule(schedule_id, 
                                          name=name,
                                          cron_expression=cron_expression,
                                          scan_type=scan_type,
                                          is_active=is_active)
        
        if success:
            flash('Schedule updated successfully!', 'success')
        else:
            flash('Error updating schedule', 'error')
            
    except Exception as e:
        flash(f'Error updating schedule: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.schedules'))

@dashboard_bp.route('/schedules/<schedule_id>/delete', methods=['POST'])
@login_required
def delete_schedule(schedule_id):
    """Delete a scan schedule"""
    try:
        scheduler = ScanScheduler()
        success = scheduler.delete_schedule(schedule_id)
        
        if success:
            flash('Schedule deleted successfully!', 'success')
        else:
            flash('Error deleting schedule', 'error')
            
    except Exception as e:
        flash(f'Error deleting schedule: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.schedules'))

@dashboard_bp.route('/schedules/<schedule_id>/run', methods=['POST'])
@login_required
def run_schedule_now(schedule_id):
    """Run a schedule immediately"""
    try:
        scheduler = ScanScheduler()
        result = scheduler.run_schedule_now(schedule_id)
        
        if result['success']:
            flash(f'Schedule executed successfully! Scans: {result.get("scans_run", 0)}, Vulnerabilities: {result.get("vulnerabilities_found", 0)}', 'success')
        else:
            flash(f'Error running schedule: {result.get("error", "Unknown error")}', 'error')
            
    except Exception as e:
        flash(f'Error running schedule: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.schedules'))

@dashboard_bp.route('/schedules/run-due', methods=['POST'])
@login_required
def run_due_scans():
    """Run all due scans"""
    try:
        scheduler = ScanScheduler()
        results = scheduler.run_due_scans()
        
        if results:
            successful = sum(1 for r in results if r['success'])
            total_vulns = sum(r.get('vulnerabilities_found', 0) for r in results)
            flash(f'Executed {len(results)} schedules ({successful} successful). Total vulnerabilities found: {total_vulns}', 'success')
        else:
            flash('No schedules were due for execution', 'info')
            
    except Exception as e:
        flash(f'Error running due scans: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.schedules'))

@dashboard_bp.route('/services/<service_id>')
@login_required
def service_detail(service_id):
    """Service detail page"""
    service = Service.query.get_or_404(service_id)
    
    # Get API versions for this service
    api_versions = ApiVersion.query.filter_by(service_id=service_id).order_by(
        ApiVersion.fetched_at.desc()
    ).all()
    
    # Get endpoints for this service
    endpoints = Endpoint.query.filter_by(service_id=service_id).order_by(
        Endpoint.path, Endpoint.method
    ).all()
    
    # Get recent scans for this service
    recent_scans = Scan.query.join(Endpoint).filter_by(
        service_id=service_id
    ).order_by(Scan.scan_time.desc()).limit(10).all()
    
    # Get vulnerabilities for this service
    vulnerabilities = Vulnerability.query.join(Scan).join(Endpoint).filter_by(
        service_id=service_id
    ).order_by(Vulnerability.severity.desc(), Vulnerability.created_at.desc()).limit(10).all()
    
    return render_template('dashboard/service_detail.html',
                         service=service,
                         api_versions=api_versions,
                         endpoints=endpoints,
                         recent_scans=recent_scans,
                         vulnerabilities=vulnerabilities)



@dashboard_bp.route('/endpoints')
@login_required
def endpoints():
    """Endpoints list page"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get filter parameters
    service_filter = request.args.get('service')
    method_filter = request.args.get('method')
    path_filter = request.args.get('path')
    risk_filter = request.args.get('risk')
    
    # Build query with filters
    query = Endpoint.query
    
    if service_filter:
        query = query.filter(Endpoint.service_id == service_filter)
    
    if method_filter:
        query = query.filter(Endpoint.method == method_filter)
    
    if path_filter:
        query = query.filter(Endpoint.path.contains(path_filter))
    
    if risk_filter:
        if risk_filter == 'high':
            query = query.filter(Endpoint.risk_score >= 7)
        elif risk_filter == 'medium':
            query = query.filter(Endpoint.risk_score >= 4, Endpoint.risk_score < 7)
        elif risk_filter == 'low':
            query = query.filter(Endpoint.risk_score < 4)
    
    endpoints = query.order_by(Endpoint.path).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get all services for the filter dropdown
    services = Service.query.order_by(Service.name).all()
    
    # Debug: Check what's in the first few endpoints
    if endpoints.items:
        first_endpoint = endpoints.items[0]
        print(f"DEBUG: First endpoint ID: {first_endpoint.id}")
        print(f"DEBUG: First endpoint path: {first_endpoint.path}")
        print(f"DEBUG: First endpoint parameters_schema: {first_endpoint.parameters_schema}")
        print(f"DEBUG: First endpoint parameters_schema type: {type(first_endpoint.parameters_schema)}")
        if first_endpoint.parameters_schema:
            print(f"DEBUG: First endpoint parameters_schema length: {len(first_endpoint.parameters_schema)}")
    
    return render_template('dashboard/endpoints.html', 
                         endpoints=endpoints,
                         services=services,
                         service_filter=service_filter,
                         method_filter=method_filter,
                         path_filter=path_filter,
                         risk_filter=risk_filter)

@dashboard_bp.route('/endpoints/<endpoint_id>')
@login_required
def endpoint_detail(endpoint_id):
    """Endpoint detail page"""
    endpoint = Endpoint.query.get_or_404(endpoint_id)
    
    # Get recent scans for this endpoint
    scans = Scan.query.filter_by(endpoint_id=endpoint_id).order_by(
        Scan.scan_time.desc()
    ).limit(10).all()
    
    # Get vulnerabilities for this endpoint
    vulnerabilities = Vulnerability.query.join(Scan).filter(
        Scan.endpoint_id == endpoint_id
    ).order_by(Vulnerability.created_at.desc()).all()
    
    # If requested as a partial (for modal), return body-only template
    is_partial = request.args.get('partial') == '1' or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    template_name = 'dashboard/endpoint_detail_partial.html' if is_partial else 'dashboard/endpoint_detail.html'
    
    return render_template(template_name,
                         endpoint=endpoint,
                         scans=scans,
                         vulnerabilities=vulnerabilities)

@dashboard_bp.route('/realtime-monitoring')
@login_required
def realtime_monitoring():
    """Real-time monitoring dashboard page"""
    return render_template('dashboard/realtime_monitoring.html')


@dashboard_bp.route('/scans')
@login_required
def scans():
    """Scans list page"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get filter parameters
    status_filter = request.args.get('status')
    type_filter = request.args.get('type')
    date_filter = request.args.get('date')
    
    # Build query with filters
    query = Scan.query
    
    if status_filter:
        query = query.filter(Scan.status == status_filter)
    
    if type_filter:
        query = query.filter(Scan.scan_type == type_filter)
    
    if date_filter:
        # Filter by date (scan_time field)
        from datetime import datetime
        try:
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d')
            next_date = filter_date.replace(day=filter_date.day + 1)
            query = query.filter(Scan.scan_time >= filter_date, Scan.scan_time < next_date)
        except ValueError:
            pass  # Invalid date format, ignore filter
    
    scans = query.order_by(Scan.scan_time.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get statistics for the current filter
    total_scans = query.count()
    completed_scans = query.filter(Scan.status == 'completed').count()
    running_scans = query.filter(Scan.status == 'running').count()
    failed_scans = query.filter(Scan.status == 'failed').count()
    
    stats = {
        'total': total_scans,
        'completed': completed_scans,
        'running': running_scans,
        'failed': failed_scans
    }
    
    return render_template('dashboard/scans.html', 
                         scans=scans,
                         stats=stats,
                         status_filter=status_filter,
                         type_filter=type_filter,
                         date_filter=date_filter)

@dashboard_bp.route('/scans/<scan_id>')
@login_required
def scan_detail(scan_id):
    """Scan detail page"""
    scan = Scan.query.get_or_404(scan_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
    
    return render_template('dashboard/scan_detail.html',
                         scan=scan,
                         vulnerabilities=vulnerabilities)

@dashboard_bp.route('/vulnerabilities')
@login_required
def vulnerabilities():
    """Vulnerabilities list page"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    severity_filter = request.args.get('severity')
    category_filter = request.args.get('category')
    status_filter = request.args.get('status')
    
    # Build query for pagination
    query = Vulnerability.query
    
    if severity_filter:
        query = query.filter(Vulnerability.severity == severity_filter)
    
    if category_filter:
        query = query.filter(Vulnerability.category == category_filter)
    
    if status_filter:
        if status_filter == 'open':
            query = query.filter(Vulnerability.false_positive == False, Vulnerability.remediated == False)
        elif status_filter == 'false_positive':
            query = query.filter(Vulnerability.false_positive == True)
        elif status_filter == 'remediated':
            query = query.filter(Vulnerability.remediated == True)
    
    # Get paginated results
    vulnerabilities = query.order_by(Vulnerability.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Calculate total statistics (unfiltered) - always show total counts
    total_vulnerabilities = Vulnerability.query.count()
    high_risk_count = Vulnerability.query.filter_by(severity='high').count()
    medium_risk_count = Vulnerability.query.filter_by(severity='medium').count()
    low_risk_count = Vulnerability.query.filter_by(severity='low').count()
    info_risk_count = Vulnerability.query.filter_by(severity='info').count()
    
    # Store original counts for display
    original_total = total_vulnerabilities
    original_high = high_risk_count
    original_medium = medium_risk_count
    original_low = low_risk_count
    original_info = info_risk_count
    
    # Apply filters to statistics if any are active
    if severity_filter or category_filter or status_filter:
        filtered_query = Vulnerability.query
        
        if severity_filter:
            filtered_query = filtered_query.filter(Vulnerability.severity == severity_filter)
        if category_filter:
            filtered_query = filtered_query.filter(Vulnerability.category == category_filter)
        if status_filter:
            if status_filter == 'open':
                filtered_query = filtered_query.filter(Vulnerability.false_positive == False, Vulnerability.remediated == False)
            elif status_filter == 'false_positive':
                filtered_query = filtered_query.filter(Vulnerability.false_positive == True)
            elif status_filter == 'remediated':
                filtered_query = filtered_query.filter(Vulnerability.remediated == True)
        
        # Update counts based on filters
        total_vulnerabilities = filtered_query.count()
        high_risk_count = filtered_query.filter_by(severity='high').count()
        medium_risk_count = filtered_query.filter_by(severity='medium').count()
        low_risk_count = filtered_query.filter_by(severity='low').count()
        info_risk_count = filtered_query.filter_by(severity='info').count()
    
    # Ensure we always show the correct counts
    # If no filters are applied, show total counts
    if not severity_filter and not category_filter and not status_filter:
        total_vulnerabilities = original_total
        high_risk_count = original_high
        medium_risk_count = original_medium
        low_risk_count = original_low
        info_risk_count = original_info
    
    return render_template('dashboard/vulnerabilities.html',
                         vulnerabilities=vulnerabilities,
                         severity_filter=severity_filter,
                         category_filter=category_filter,
                         status_filter=status_filter,
                         total_vulnerabilities=total_vulnerabilities,
                         high_risk_count=high_risk_count,
                         medium_risk_count=medium_risk_count,
                         low_risk_count=low_risk_count,
                         info_risk_count=info_risk_count)

@dashboard_bp.route('/vulnerabilities/<vulnerability_id>')
@login_required
def vulnerability_detail(vulnerability_id):
    """Vulnerability detail page"""
    vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
    
    return render_template('dashboard/vulnerability_detail.html',
                         vulnerability=vulnerability)

@dashboard_bp.route('/api/vulnerability-modal/<vulnerability_id>')
@login_required
def vulnerability_modal(vulnerability_id):
    """Get vulnerability details for modal"""
    vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
    
    # Get related scan and endpoint information
    scan = Scan.query.get(vulnerability.scan_id) if vulnerability.scan_id else None
    endpoint = Endpoint.query.get(vulnerability.endpoint_id) if vulnerability.endpoint_id else None
    service = Service.query.get(vulnerability.service_id) if vulnerability.service_id else None
    
    return render_template('dashboard/vulnerability_modal_content.html',
                         vulnerability=vulnerability,
                         scan=scan,
                         endpoint=endpoint,
                         service=service)

@dashboard_bp.route('/api/scan-modal/<scan_id>')
@login_required
def scan_modal(scan_id):
    """Get scan details for modal"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Get related endpoint and service information
    endpoint = Endpoint.query.get(scan.endpoint_id) if scan.endpoint_id else None
    service = Service.query.get(endpoint.service_id) if endpoint else None
    
    # Get vulnerabilities for this scan
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
    
    return render_template('dashboard/scan_modal_content.html',
                         scan=scan,
                         endpoint=endpoint,
                         service=service,
                         vulnerabilities=vulnerabilities)

@dashboard_bp.route('/api/change-modal/<service_id>')
@login_required
def change_modal(service_id):
    """Get change details for modal"""
    service = Service.query.get_or_404(service_id)
    
    # Get recent endpoints for this service
    endpoints = Endpoint.query.filter_by(service_id=service_id).limit(10).all()
    
    return render_template('dashboard/change_modal_content.html',
                         service=service,
                         endpoints=endpoints)

@dashboard_bp.route('/api/trigger-scan/<endpoint_id>', methods=['POST'])
@login_required
def trigger_scan(endpoint_id):
    """Trigger a scan for an endpoint"""
    try:
        endpoint = Endpoint.query.get_or_404(endpoint_id)
        scan_type = request.json.get('scan_type', 'combined')
        
        # Create a new scan record first
        from app.models import Scan
        from datetime import datetime
        
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
        
        # Queue scan task with the scan ID
        task = scan_endpoint.delay(scan.id, scan.scan_config)
        
        flash(f'Scan queued for endpoint {endpoint.path}', 'success')
        return jsonify({'status': 'success', 'task_id': task.id, 'scan_id': scan.id})
        
    except Exception as e:
        flash(f'Failed to trigger scan: {str(e)}', 'error')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@dashboard_bp.route('/api/scan-status/<task_id>')
@login_required
def scan_status(task_id):
    """Get scan status for a task"""
    try:
        from celery.result import AsyncResult
        
        # Get task result
        task_result = AsyncResult(task_id)
        
        if task_result.ready():
            if task_result.successful():
                result = task_result.result
                return jsonify({
                    'status': 'completed',
                    'vulnerabilities_found': result.get('vulnerabilities_found', 0),
                    'duration': result.get('duration', 0)
                })
            else:
                return jsonify({
                    'status': 'failed',
                    'error': str(task_result.info)
                })
        else:
            return jsonify({
                'status': 'running',
                'progress': 'Scan in progress...'
            })
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@dashboard_bp.route('/api/trigger-service-discovery', methods=['POST'])
@login_required
def trigger_service_discovery():
    """Trigger service discovery"""
    try:
        # Queue service discovery task
        task = crawl_and_update_services.delay()
        
        flash('Service discovery queued', 'success')
        return jsonify({'status': 'success', 'task_id': task.id})
        
    except Exception as e:
        flash(f'Failed to trigger service discovery: {str(e)}', 'error')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@dashboard_bp.route('/api/test-slack', methods=['POST'])
@login_required
def test_slack():
    """Test Slack integration"""
    try:
        notifier = slack_notifier
        success = notifier.send_test_message()
        
        if success:
            flash('Slack test message sent successfully', 'success')
            return jsonify({'status': 'success'})
        else:
            flash('Failed to send Slack test message', 'error')
            return jsonify({'status': 'error', 'message': 'Slack test failed'})
            
    except Exception as e:
        flash(f'Slack test failed: {str(e)}', 'error')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@dashboard_bp.route('/api/update-parameter-values/<endpoint_id>', methods=['POST'])
@login_required
def update_parameter_values(endpoint_id):
    """Update parameter values for an endpoint"""
    try:
        endpoint = Endpoint.query.get_or_404(endpoint_id)
        param_values = request.json.get('param_values', {})
        
        # Update endpoint parameter values
        endpoint.param_values = param_values
        endpoint.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        flash('Parameter values updated successfully', 'success')
        return jsonify({'status': 'success'})
        
    except Exception as e:
        flash(f'Failed to update parameter values: {str(e)}', 'error')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@dashboard_bp.route('/api/mark-vulnerability-false-positive/<vulnerability_id>', methods=['POST'])
@login_required
def mark_vulnerability_false_positive(vulnerability_id):
    """Mark a vulnerability as false positive"""
    try:
        vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
        vulnerability.false_positive = True
        vulnerability.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        flash('Vulnerability marked as false positive', 'success')
        return jsonify({'status': 'success'})
        
    except Exception as e:
        flash(f'Failed to mark vulnerability: {str(e)}', 'error')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@dashboard_bp.route('/api/mark-vulnerability-remediated/<vulnerability_id>', methods=['POST'])
@login_required
def mark_vulnerability_remediated(vulnerability_id):
    """Mark a vulnerability as remediated"""
    try:
        vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
        vulnerability.remediated = True
        vulnerability.remediated_at = datetime.now(timezone.utc)
        vulnerability.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        flash('Vulnerability marked as remediated', 'success')
        return jsonify({'status': 'success'})
        
    except Exception as e:
        flash(f'Failed to mark vulnerability: {str(e)}', 'error')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@dashboard_bp.route('/reports')
@login_required
def reports():
    """Reports page"""
    # Get date range from query parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
    else:
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
    
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d')
    else:
        end_date = datetime.now(timezone.utc)
    
    # Get scan statistics for the date range
    scan_stats = db.session.query(
        Scan.status,
        db.func.count(Scan.id).label('count')
    ).filter(
        Scan.scan_time >= start_date,
        Scan.scan_time <= end_date
    ).group_by(Scan.status).all()
    
    # Get vulnerability statistics
    vuln_stats = db.session.query(
        Vulnerability.severity,
        db.func.count(Vulnerability.id).label('count')
    ).join(Scan).filter(
        Scan.scan_time >= start_date,
        Scan.scan_time <= end_date
    ).group_by(Vulnerability.severity).all()
    
    # Get top vulnerable services
    top_vulnerable_services = db.session.query(
        Service.name,
        db.func.count(Vulnerability.id).label('vuln_count')
    ).join(Endpoint).join(Scan).join(Vulnerability).filter(
        Scan.scan_time >= start_date,
        Scan.scan_time <= end_date
    ).group_by(Service.id, Service.name).order_by(
        db.func.count(Vulnerability.id).desc()
    ).limit(10).all()
    
    return render_template('dashboard/reports.html',
                         start_date=start_date,
                         end_date=end_date,
                         scan_stats=scan_stats,
                         vuln_stats=vuln_stats,
                         top_vulnerable_services=top_vulnerable_services)

@dashboard_bp.route('/add-service', methods=['POST'])
@login_required
def add_service():
    """Add a new service"""
    try:
        name = request.form.get('name')
        url = request.form.get('url')
        description = request.form.get('description', '')
        
        if not name or not url:
            flash('Name and URL are required', 'error')
            return redirect(url_for('dashboard.services'))
        
        # Check if service already exists
        existing_service = Service.query.filter_by(url=url).first()
        if existing_service:
            flash('Service with this URL already exists', 'error')
            return redirect(url_for('dashboard.services'))
        
        # Create new service
        service = Service(
            name=name,
            url=url,
            description=description,
            status='active'
        )
        
        db.session.add(service)
        db.session.commit()
        
        flash(f'Service "{name}" added successfully!', 'success')
        
    except Exception as e:
        flash(f'Error adding service: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.services'))

@dashboard_bp.route('/import-services', methods=['POST'])
@login_required
def import_services():
    """Import services from file"""
    try:
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('dashboard.services'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('dashboard.services'))
        
        if file and file.filename.endswith('.json'):
            import json
            data = json.load(file)
            
            if not isinstance(data, list):
                flash('Invalid JSON format. Expected array of services.', 'error')
                return redirect(url_for('dashboard.services'))
            
            added_count = 0
            for service_data in data:
                if 'name' in service_data and 'url' in service_data:
                    # Check if service already exists
                    existing = Service.query.filter_by(url=service_data['url']).first()
                    if not existing:
                        service = Service(
                            name=service_data['name'],
                            url=service_data['url'],
                            description=service_data.get('description', ''),
                            status='active'
                        )
                        db.session.add(service)
                        added_count += 1
            
            db.session.commit()
            flash(f'{added_count} services imported successfully!', 'success')
            
        else:
            flash('Unsupported file format. Please use JSON.', 'error')
            
    except Exception as e:
        flash(f'Error importing services: {str(e)}', 'error')
    
    return redirect(url_for('dashboard.services'))

@dashboard_bp.route('/run-service-scan/<service_id>', methods=['POST'])
@login_required
def run_service_scan(service_id):
    """Run scan for a specific service"""
    try:
        service = Service.query.get_or_404(service_id)
        
        # Get all endpoints for this service
        endpoints = Endpoint.query.filter_by(service_id=service.id).all()
        
        if not endpoints:
            return jsonify({
                'success': False,
                'error': 'No endpoints found for this service'
            })
        
        # Create scan tasks for each endpoint
        scan_count = 0
        for endpoint in endpoints:
            try:
                # Create scan record
                scan = Scan(
                    endpoint_id=endpoint.id,
                    scan_type='combined',
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
                
                # Queue scan task
                from app.tasks import scan_endpoint
                scan_endpoint.delay(scan.id, scan.scan_config)
                scan_count += 1
                
            except Exception as e:
                continue
        
        if scan_count > 0:
            return jsonify({
                'success': True,
                'message': f'Started {scan_count} scans for {service.name}',
                'scan_count': scan_count
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to start any scans'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/settings')
@login_required
def settings():
    """Settings page"""
    return render_template('dashboard/settings.html')

@dashboard_bp.route('/manual-parameter/<endpoint_id>', methods=['POST'])
@login_required
def add_manual_parameter(endpoint_id):
    """Add manual parameter values for an endpoint"""
    try:
        endpoint = Endpoint.query.get_or_404(endpoint_id)
        
        parameter_name = request.form.get('parameter_name')
        parameter_value = request.form.get('parameter_value')
        parameter_type = request.form.get('parameter_type', 'string')
        
        if not parameter_name or not parameter_value:
            return jsonify({
                'success': False,
                'error': 'Parameter name and value are required'
            })
        
        # Get current parameter values
        current_params = endpoint.param_values or {}
        
        # Add new parameter
        current_params[parameter_name] = {
            'value': parameter_value,
            'type': parameter_type,
            'source': 'manual',
            'added_by': current_user.username,
            'added_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Update endpoint
        endpoint.param_values = current_params
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Parameter "{parameter_name}" added successfully',
            'parameter': current_params[parameter_name]
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/validate-parameter/<endpoint_id>', methods=['POST'])
@login_required
def validate_parameter(endpoint_id):
    """Validate a parameter value against the endpoint"""
    try:
        endpoint = Endpoint.query.get_or_404(endpoint_id)
        
        parameter_name = request.form.get('parameter_name')
        parameter_value = request.form.get('parameter_value')
        
        if not parameter_name or not parameter_value:
            return jsonify({
                'success': False,
                'error': 'Parameter name and value are required'
            })
        
        # Build test URL with parameter
        from app.utils.scanner import SecurityScanner
        scanner = SecurityScanner()
        
        # Create endpoint dict for the scanner
        endpoint_dict = {
            'path': endpoint.path,
            'service_api_url': endpoint.service.api_url if endpoint.service else None
        }
        
        test_params = {parameter_name: parameter_value}
        test_url = scanner._build_target_url(endpoint_dict, test_params)
        
        # Make test request
        import requests
        from app.config import Config
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Add authorization if configured
        if Config.API_AUTHORIZATION_HEADER:
            if Config.API_AUTHORIZATION_TYPE.lower() == 'basic':
                # For Basic auth, the token should already be base64 encoded
                headers['Authorization'] = f"Basic {Config.API_AUTHORIZATION_HEADER}"
            else:
                headers['Authorization'] = f"{Config.API_AUTHORIZATION_TYPE} {Config.API_AUTHORIZATION_HEADER}"
        
        # Add any additional headers from config
        if Config.API_HEADERS:
            try:
                import json
                additional_headers = json.loads(Config.API_HEADERS)
                headers.update(additional_headers)
            except (json.JSONDecodeError, TypeError):
                pass
        
        # Debug: Log the headers being sent
        print(f"DEBUG: Test URL: {test_url}")
        print(f"DEBUG: Headers: {headers}")
        print(f"DEBUG: Auth type: {Config.API_AUTHORIZATION_TYPE}")
        print(f"DEBUG: Auth header value: {Config.API_AUTHORIZATION_HEADER[:20]}...")
        
        response = requests.get(
            test_url,
            headers=headers,
            timeout=10
        )
        
        # Debug: Log the response
        print(f"DEBUG: Response status: {response.status_code}")
        print(f"DEBUG: Response headers: {dict(response.headers)}")
        if response.status_code != 200:
            print(f"DEBUG: Response body: {response.text[:500]}")
        
        is_valid = response.status_code in [200, 201, 202]
        
        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'test_url': test_url
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/api/statistics')
@login_required
def api_statistics():
    """API endpoint for dashboard statistics"""
    try:
        # Get basic statistics
        total_services = Service.query.count()
        total_endpoints = Endpoint.query.count()
        total_scans = Scan.query.count()
        total_vulnerabilities = Vulnerability.query.count()
        
        # Get recent activity
        recent_scans = Scan.query.order_by(Scan.scan_time.desc()).limit(5).all()
        recent_vulnerabilities = Vulnerability.query.order_by(
            Vulnerability.created_at.desc()
        ).limit(5).all()
        
        # Get vulnerability counts by severity
        severity_counts = db.session.query(
            Vulnerability.severity,
            db.func.count(Vulnerability.id).label('count')
        ).group_by(Vulnerability.severity).all()
        
        # Get scan status counts
        scan_status_counts = db.session.query(
            Scan.status,
            db.func.count(Scan.id).label('count')
        ).group_by(Scan.status).all()
        
        return jsonify({
            'total_services': total_services,
            'total_endpoints': total_endpoints,
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities,
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
            ],
            'severity_counts': {
                item.severity: item.count for item in severity_counts
            },
            'scan_status_counts': {
                item.status: item.count for item in scan_status_counts
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/generate-description/<endpoint_id>', methods=['POST'])
@login_required
def generate_description(endpoint_id):
    """Generate AI description for an endpoint"""
    try:
        endpoint = Endpoint.query.get_or_404(endpoint_id)
        
        ai_generator = AIDescriptionGenerator()
        endpoint_data = {
            'method': endpoint.method,
            'path': endpoint.path,
            'summary': endpoint.summary,
            'description': endpoint.description,
            'parameters_schema': endpoint.parameters_schema,
            'request_body_schema': endpoint.request_body_schema
        }
        
        result = ai_generator.generate_endpoint_description(endpoint_data)
        
        return jsonify({
            'success': True,
            'description': result['description'],
            'security_analysis': result['security_analysis'],
            'risk_assessment': result['risk_assessment'],
            'recommendations': result['recommendations']
        })
        
    except Exception as e:
        import traceback
        logger.error(f"Error generating AI description: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/test-slack-notification', methods=['POST'])
@login_required
def test_slack_notification():
    """Test Slack notification"""
    try:
        success = slack_notifier.test_connection()
        return jsonify({
            'success': success,
            'message': 'Slack notification test completed'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/send-daily-summary', methods=['POST'])
@login_required
def send_daily_summary():
    """Send daily summary notification"""
    try:
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
        
        medium_risk = Vulnerability.query.filter(
            Vulnerability.created_at >= start_of_day,
            Vulnerability.created_at <= end_of_day,
            Vulnerability.severity == 'medium'
        ).count()
        
        low_risk = Vulnerability.query.filter(
            Vulnerability.created_at >= start_of_day,
            Vulnerability.created_at <= end_of_day,
            Vulnerability.severity == 'low'
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
            'medium_risk': medium_risk,
            'low_risk': low_risk,
            'scans_run': scans_run,
            'services_scanned': services_scanned,
            'endpoints_scanned': endpoints_scanned,
            'date': today.isoformat()
        }
        
        # Send daily summary notification (simplified)
        try:
            notification_data = NotificationData(
                type=NotificationType.SCAN_COMPLETED,  # Use existing type
                title='Daily Security Summary',
                message=f'Daily scan summary: {total_vulnerabilities} vulnerabilities found across {services_scanned} services',
                severity='warning' if total_vulnerabilities > 0 else 'info',
                data=summary_data
            )
            success = slack_notifier.send_notification(notification_data)
        except Exception as e:
            logger.error(f"Failed to send daily summary: {e}")
            success = False
        
        return jsonify({
            'success': success,
            'summary': summary_data,
            'message': 'Daily summary sent to Slack'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/api/start-scan', methods=['POST'])
@login_required
def start_scan():
    """API endpoint to start a scan from the dashboard modal"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('target'):
            return jsonify({'success': False, 'message': 'Scan target is required'}), 400
        
        if not data.get('tools') or len(data['tools']) == 0:
            return jsonify({'success': False, 'message': 'At least one security tool must be selected'}), 400
        
        # Get scan configuration
        target = data['target']
        service_id = data.get('serviceId')
        tools = data['tools']
        scan_depth = data.get('scanDepth', 'standard')
        timeout = data.get('timeout', 30)
        notifications = data.get('notifications', True)
        save_parameters = data.get('saveParameters', True)
        
        # Determine endpoints to scan
        if target == 'all':
            # Scan all endpoints from all services
            endpoints = Endpoint.query.all()
        elif target == 'specific' and service_id:
            # Scan endpoints from specific service
            endpoints = Endpoint.query.filter_by(service_id=service_id).all()
        else:
            return jsonify({'success': False, 'message': 'Invalid scan target configuration'}), 400
        
        if not endpoints:
            return jsonify({'success': False, 'message': 'No endpoints found to scan'}), 400
        
        # Start scans for each endpoint
        scan_count = 0
        created_scans = []
        
        for endpoint in endpoints:
            try:
                # Create scan configuration
                scan_config = {
                    'scan_depth': scan_depth,
                    'timeout': timeout,
                    'tools': tools,
                    'notifications': notifications,
                    'save_parameters': save_parameters
                }
                
                # Create scan record immediately with "running" status
                from app.models import Scan
                scan = Scan(
                    endpoint_id=endpoint.id,
                    scan_type='security',
                    status='running',
                    scan_time=datetime.now(timezone.utc),
                    tools_used=','.join(tools),
                    scan_config=json.dumps(scan_config)
                )
                db.session.add(scan)
                db.session.flush()  # Get the scan ID
                
                # Start the scan task
                from app.tasks import scan_endpoint
                task = scan_endpoint.delay(scan.id, scan_config)
                
                # Store scan info for response
                created_scans.append({
                    'id': scan.id,
                    'endpoint': endpoint.path,
                    'service': endpoint.service.name if endpoint.service else 'Unknown',
                    'task_id': task.id
                })
                
                scan_count += 1
                
            except Exception as e:
                logger.error(f"Failed to start scan for endpoint {endpoint.id}: {e}")
                continue
        
        # Commit all scan records
        db.session.commit()
        
        if scan_count == 0:
            return jsonify({'success': False, 'message': 'Failed to start any scans'}), 500
        
        # Send notification if enabled
        if notifications:
            try:
                from app.utils.slack_notifier import slack_notifier
                target_desc = f"all {len(endpoints)} endpoints" if target == 'all' else f"service {endpoint.service.name if endpoint.service else 'Unknown'}"
                # Prepare scan data for notification
                scan_data = {
                    'scan_type': 'manual',
                    'service_name': endpoint.service.name if endpoint.service else 'Unknown',
                    'endpoint_path': target_desc,
                    'endpoint_method': 'MULTIPLE' if target == 'all' else endpoint.method,
                    'tools_used': tools,
                    'scan_id': f"manual-{int(datetime.now().timestamp())}",
                    'is_service_scan': target == 'all'
                }
                
                slack_notifier.send_scan_started(scan_data)
            except Exception as e:
                logger.warning(f"Failed to send Slack notification: {e}")
        
        return jsonify({
            'success': True,
            'message': f'Started {scan_count} scan(s) successfully',
            'scan_count': scan_count,
            'scans': created_scans,
            'redirect_url': '/scans'
        })
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'success': False, 'message': f'Internal server error: {str(e)}'}), 500

@dashboard_bp.route('/api/discover-services', methods=['POST'])
@login_required
def api_discover_services():
    """API endpoint to discover services from ngrok and API base URLs"""
    try:
        data = request.get_json()
        sources = data.get('sources', ['ngrok', 'api_base'])
        manual = data.get('manual', False)
        
        services_found = 0
        discovered_services = []
        
        # Discover from ngrok tunnel
        if 'ngrok' in sources:
            try:
                from app.utils.crawler import crawl_and_update
                result = crawl_and_update()
                if result and isinstance(result, dict):
                    services_found += result.get('services_found', 0)
                    discovered_services.extend(result.get('services', []))
            except Exception as e:
                logger.error(f"Error discovering from ngrok: {e}")
                if manual:
                    return jsonify({'success': False, 'message': f'Ngrok discovery failed: {str(e)}'}), 500
        
        # Discover from API base URL
        if 'api_base' in sources:
            try:
                from app.utils.crawler import crawl_api_base_url
                result = crawl_api_base_url()
                if result and isinstance(result, dict):
                    services_found += result.get('services_found', 0)
                    discovered_services.extend(result.get('services', []))
            except Exception as e:
                logger.error(f"Error discovering from API base: {e}")
                if manual:
                    return jsonify({'success': False, 'message': f'API base discovery failed: {str(e)}'}), 500
        
        # Update discovery settings
        if manual:
            try:
                from app.utils.discovery_manager import update_discovery_stats
                update_discovery_stats(
                    last_run=datetime.now(timezone.utc),
                    services_found=services_found,
                    status='success'
                )
            except Exception as e:
                logger.warning(f"Failed to update discovery stats: {e}")
        
        # Send notification if services were found
        if services_found > 0:
            try:
                from app.utils.slack_notifier import slack_notifier
                # Send service discovery notification using the new system
                notification_data = NotificationData(
                    type=NotificationType.SCAN_STARTED,  # Use existing type
                    title='Service Discovery Completed',
                    message=f'Service discovery completed: {services_found} services found from {", ".join(sources)}',
                    severity='info',
                    data={
                        'services_found': services_found,
                        'sources': sources,
                        'timestamp': datetime.now().isoformat()
                    }
                )
                slack_notifier.send_notification(notification_data)
            except Exception as e:
                logger.warning(f"Failed to send discovery notification: {e}")
        
        return jsonify({
            'success': True,
            'message': f'Discovery completed successfully',
            'services_found': services_found,
            'discovered_services': discovered_services
        })
        
    except Exception as e:
        logger.error(f"Error in service discovery: {e}")
        return jsonify({'success': False, 'message': f'Discovery failed: {str(e)}'}), 500

@dashboard_bp.route('/api/discovery-settings', methods=['GET', 'POST'])
@login_required
def discovery_settings():
    """API endpoint to manage automatic discovery settings"""
    try:
        if request.method == 'GET':
            # Get current settings
            from app.utils.discovery_manager import get_discovery_settings
            settings = get_discovery_settings()
            return jsonify({'success': True, 'settings': settings})
        
        elif request.method == 'POST':
            # Update settings
            data = request.get_json()
            enabled = data.get('enabled', True)
            interval = data.get('interval', 60)  # minutes
            sources = data.get('sources', ['ngrok', 'api_base'])
            
            from app.utils.discovery_manager import update_discovery_settings
            update_discovery_settings(
                enabled=enabled,
                interval=interval,
                sources=sources
            )
            
            return jsonify({'success': True, 'message': 'Discovery settings updated successfully'})
            
    except Exception as e:
        logger.error(f"Error managing discovery settings: {e}")
        return jsonify({'success': False, 'message': f'Settings operation failed: {str(e)}'}), 500

@dashboard_bp.route('/api/scan-management/cleanup-stuck', methods=['POST'])
@login_required
def cleanup_stuck_scans():
    """API endpoint to clean up scans stuck in RUNNING status"""
    try:
        from app.tasks import cleanup_stuck_scans
        result = cleanup_stuck_scans.delay()
        
        return jsonify({
            'success': True,
            'message': 'Cleanup task started',
            'task_id': result.id
        })
        
    except Exception as e:
        logger.error(f"Error starting cleanup task: {e}")
        return jsonify({'success': False, 'message': f'Cleanup failed: {str(e)}'}), 500

@dashboard_bp.route('/api/scan-management/retry-failed', methods=['POST'])
@login_required
def retry_failed_scans():
    """API endpoint to retry failed scans"""
    try:
        data = request.get_json() or {}
        max_retries = data.get('max_retries', 3)
        
        from app.tasks import retry_failed_scans
        result = retry_failed_scans.delay(max_retries)
        
        return jsonify({
            'success': True,
            'message': 'Retry task started',
            'task_id': result.id,
            'max_retries': max_retries
        })
        
    except Exception as e:
        logger.error(f"Error starting retry task: {e}")
        return jsonify({'success': False, 'message': f'Retry failed: {str(e)}'}), 500


@dashboard_bp.route('/api/scan-management/retry-pending', methods=['POST'])
@login_required
def retry_pending_scans():
    """API endpoint to retry pending scans"""
    try:
        from app.tasks import retry_pending_scans
        result = retry_pending_scans.delay()
        
        return jsonify({
            'success': True,
            'message': 'Retry pending scans task started',
            'task_id': result.id
        })
        
    except Exception as e:
        logger.error(f"Error starting retry pending scans task: {e}")
        return jsonify({'success': False, 'message': f'Retry pending scans failed: {str(e)}'}), 500

@dashboard_bp.route('/api/test-zap-compatibility', methods=['POST'])
@login_required
def test_zap_compatibility():
    """API endpoint to test ZAP API compatibility"""
    try:
        from app.utils.scanner import test_zap_compatibility
        
        compatibility_results = test_zap_compatibility()
        
        return jsonify({
            'success': True,
            'compatibility': compatibility_results
        })
        
    except Exception as e:
        logger.error(f"Error testing ZAP compatibility: {e}")
        return jsonify({'success': False, 'message': f'ZAP compatibility test failed: {str(e)}'}), 500


@dashboard_bp.route('/api/realtime-monitoring/status', methods=['GET'])
@login_required
def realtime_monitoring_status():
    """API endpoint to get real-time monitoring status"""
    try:
        from app.utils.realtime_monitor import get_realtime_status, get_recent_changes, get_scan_activity_log, get_baseline_status
        
        status = get_realtime_status()
        recent_changes = get_recent_changes(hours=24)
        scan_activity = get_scan_activity_log(hours=24)
        baseline_status = get_baseline_status()
        
        return jsonify({
            'success': True,
            'status': status,
            'recent_changes': recent_changes,
            'scan_activity': scan_activity,
            'baseline_status': baseline_status
        })
        
    except Exception as e:
        logger.error(f"Error getting real-time monitoring status: {e}")
        return jsonify({'success': False, 'message': f'Status check failed: {str(e)}'}), 500


@dashboard_bp.route('/api/realtime-monitoring/start', methods=['POST'])
@login_required
def start_realtime_monitoring():
    """API endpoint to start real-time monitoring"""
    try:
        from app.utils.realtime_monitor import start_realtime_monitoring
        
        start_realtime_monitoring()
        
        return jsonify({
            'success': True,
            'message': 'Real-time monitoring started successfully'
        })
        
    except Exception as e:
        logger.error(f"Error starting real-time monitoring: {e}")
        return jsonify({'success': False, 'message': f'Failed to start monitoring: {str(e)}'}), 500


@dashboard_bp.route('/api/realtime-monitoring/stop', methods=['POST'])
@login_required
def stop_realtime_monitoring():
    """API endpoint to stop real-time monitoring"""
    try:
        from app.utils.realtime_monitor import stop_realtime_monitoring
        
        stop_realtime_monitoring()
        
        return jsonify({
            'success': True,
            'message': 'Real-time monitoring stopped successfully'
        })
        
    except Exception as e:
        logger.error(f"Error stopping real-time monitoring: {e}")
        return jsonify({'success': False, 'message': f'Failed to stop monitoring: {str(e)}'}), 500

@dashboard_bp.route('/api/realtime-monitoring/establish-baseline', methods=['POST'])
@login_required
def establish_baseline():
    """API endpoint to manually establish baseline snapshot"""
    try:
        from app.utils.realtime_monitor import establish_baseline
        
        success = establish_baseline()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Baseline established successfully'
            })
        else:
            return jsonify({'success': False, 'message': 'Failed to establish baseline'}), 500
        
    except Exception as e:
        logger.error(f"Error establishing baseline: {e}")
        return jsonify({'success': False, 'message': f'Failed to establish baseline: {str(e)}'}), 500

@dashboard_bp.route('/api/realtime-monitoring/reset-baseline', methods=['POST'])
@login_required
def reset_baseline():
    """API endpoint to reset baseline snapshot"""
    try:
        from app.utils.realtime_monitor import reset_baseline
        
        success = reset_baseline()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Baseline reset successfully'
            })
        else:
            return jsonify({'success': False, 'message': 'Failed to reset baseline'}), 500
        
    except Exception as e:
        logger.error(f"Error resetting baseline: {e}")
        return jsonify({'success': False, 'message': f'Failed to reset baseline: {str(e)}'}), 500

@dashboard_bp.route('/api/realtime-monitoring/enable-scanning', methods=['POST'])
@login_required
def enable_auto_scanning():
    """API endpoint to enable auto-scanning"""
    try:
        from app.utils.realtime_monitor import enable_auto_scanning
        
        success = enable_auto_scanning()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Auto-scanning enabled successfully'
            })
        else:
            return jsonify({'success': False, 'message': 'Cannot enable auto-scanning: No baseline established'}), 400
        
    except Exception as e:
        logger.error(f"Error enabling auto-scanning: {e}")
        return jsonify({'success': False, 'message': f'Failed to enable auto-scanning: {str(e)}'}), 500

@dashboard_bp.route('/api/realtime-monitoring/disable-scanning', methods=['POST'])
@login_required
def disable_auto_scanning():
    """API endpoint to disable auto-scanning"""
    try:
        from app.utils.realtime_monitor import disable_auto_scanning
        
        success = disable_auto_scanning()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Auto-scanning disabled successfully'
            })
        else:
            return jsonify({'success': False, 'message': 'Failed to disable auto-scanning'}), 500
        
    except Exception as e:
        logger.error(f"Error disabling auto-scanning: {e}")
        return jsonify({'success': False, 'message': f'Failed to disable auto-scanning: {str(e)}'}), 500


@dashboard_bp.route('/api/realtime-monitoring/config', methods=['POST'])
@login_required
def update_realtime_config():
    """API endpoint to update real-time monitoring configuration"""
    try:
        data = request.get_json() or {}
        
        from app.utils.realtime_monitor import update_realtime_config
        
        # Update configuration
        update_realtime_config(**data)
        
        return jsonify({
            'success': True,
            'message': 'Real-time monitoring configuration updated successfully'
        })
        
    except Exception as e:
        logger.error(f"Error updating real-time monitoring config: {e}")
        return jsonify({'success': False, 'message': f'Configuration update failed: {str(e)}'}), 500


@dashboard_bp.route('/api/scan-management/status', methods=['GET'])
@login_required
def scan_management_status():
    """API endpoint to get scan management status"""
    try:
        # Get counts of different scan statuses
        total_scans = Scan.query.count()
        running_scans = Scan.query.filter_by(status='running').count()
        failed_scans = Scan.query.filter_by(status='failed').count()
        completed_scans = Scan.query.filter_by(status='completed').count()
        
        # Get scans that might be stuck (running for more than 15 minutes)
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=15)
        stuck_scans = Scan.query.filter(
            Scan.status == 'running',
            Scan.scan_time < cutoff_time
        ).count()
        
        return jsonify({
            'success': True,
            'status': {
                'total_scans': total_scans,
                'running_scans': running_scans,
                'failed_scans': failed_scans,
                'completed_scans': completed_scans,
                'potentially_stuck': stuck_scans
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'success': False, 'message': f'Status check failed: {str(e)}'}), 500


@dashboard_bp.route('/api/data-cleanup/sync', methods=['POST'])
@login_required
def sync_with_portal():
    """API endpoint to synchronize database with portal"""
    try:
        from app.utils.data_cleanup import data_cleanup_manager
        
        logger.info("Starting portal synchronization...")
        results = data_cleanup_manager.sync_with_portal()
        
        return jsonify({
            'success': True,
            'message': 'Portal synchronization completed',
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error during portal sync: {e}")
        return jsonify({'success': False, 'message': f'Sync failed: {str(e)}'}), 500


@dashboard_bp.route('/api/data-cleanup/cleanup', methods=['POST'])
@login_required
def cleanup_database():
    """API endpoint to perform database cleanup"""
    try:
        from app.utils.data_cleanup import data_cleanup_manager
        
        logger.info("Starting database cleanup...")
        results = data_cleanup_manager.full_cleanup()
        
        return jsonify({
            'success': True,
            'message': 'Database cleanup completed',
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error during database cleanup: {e}")
        return jsonify({'success': False, 'message': f'Cleanup failed: {str(e)}'}), 500


@dashboard_bp.route('/api/data-cleanup/stats', methods=['GET'])
@login_required
def get_database_stats():
    """API endpoint to get database statistics"""
    try:
        from app.utils.data_cleanup import data_cleanup_manager
        
        stats = data_cleanup_manager.get_database_stats()
        
        return jsonify({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting database stats: {e}")
        return jsonify({'success': False, 'message': f'Stats retrieval failed: {str(e)}'}), 500
