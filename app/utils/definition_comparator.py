"""
API Definition Comparator for detecting changes and triggering scans
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from app import db
from app.models import Service, ApiVersion, Endpoint, Scan
from app.utils.scanner import SecurityScanner

logger = logging.getLogger(__name__)

class APIDefinitionComparator:
    """Comparator for API definitions to detect changes and trigger scans"""
    
    def __init__(self):
        self.scanner = SecurityScanner()
    
    def calculate_definition_hash(self, spec: Dict) -> str:
        """
        Calculate a hash for the API definition to detect changes
        
        Args:
            spec: OpenAPI specification dictionary
            
        Returns:
            SHA256 hash of the normalized specification
        """
        # Normalize the spec by removing timestamps and other volatile fields
        normalized_spec = self._normalize_spec(spec)
        
        # Convert to JSON string with sorted keys for consistent hashing
        spec_string = json.dumps(normalized_spec, sort_keys=True, separators=(',', ':'))
        
        # Calculate SHA256 hash
        return hashlib.sha256(spec_string.encode('utf-8')).hexdigest()
    
    def _normalize_spec(self, spec: Dict) -> Dict:
        """
        Normalize API specification by removing volatile fields
        
        Args:
            spec: Original OpenAPI specification
            
        Returns:
            Normalized specification
        """
        import copy
        normalized = copy.deepcopy(spec)
        
        # Remove volatile fields that shouldn't affect change detection
        volatile_fields = [
            'x-timestamp',
            'x-generated-at',
            'x-last-modified',
            'x-version-hash'
        ]
        
        def remove_volatile_fields(obj):
            if isinstance(obj, dict):
                for field in volatile_fields:
                    obj.pop(field, None)
                for value in obj.values():
                    remove_volatile_fields(value)
            elif isinstance(obj, list):
                for item in obj:
                    remove_volatile_fields(item)
        
        remove_volatile_fields(normalized)
        return normalized
    
    def compare_definitions(self, old_spec: Dict, new_spec: Dict) -> Dict:
        """
        Compare two API definitions and return differences
        
        Args:
            old_spec: Previous API specification
            new_spec: Current API specification
            
        Returns:
            Dictionary containing comparison results
        """
        comparison = {
            'has_changes': False,
            'change_types': [],
            'added_endpoints': [],
            'removed_endpoints': [],
            'modified_endpoints': [],
            'added_parameters': [],
            'removed_parameters': [],
            'modified_parameters': [],
            'version_changes': {},
            'summary': {}
        }
        
        try:
            # Compare versions
            old_version = old_spec.get('info', {}).get('version', '1.0.0')
            new_version = new_spec.get('info', {}).get('version', '1.0.0')
            
            if old_version != new_version:
                comparison['version_changes'] = {
                    'old_version': old_version,
                    'new_version': new_version
                }
                comparison['change_types'].append('version_change')
                comparison['has_changes'] = True
            
            # Compare paths
            old_paths = old_spec.get('paths', {})
            new_paths = new_spec.get('paths', {})
            
            # Find added endpoints
            for path, path_item in new_paths.items():
                if path not in old_paths:
                    for method in path_item.keys():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                            comparison['added_endpoints'].append({
                                'path': path,
                                'method': method.upper(),
                                'operation_id': path_item[method].get('operationId')
                            })
                            comparison['change_types'].append('endpoint_added')
                            comparison['has_changes'] = True
            
            # Find removed endpoints
            for path, path_item in old_paths.items():
                if path not in new_paths:
                    for method in path_item.keys():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                            comparison['removed_endpoints'].append({
                                'path': path,
                                'method': method.upper(),
                                'operation_id': path_item[method].get('operationId')
                            })
                            comparison['change_types'].append('endpoint_removed')
                            comparison['has_changes'] = True
            
            # Find modified endpoints
            for path in old_paths.keys():
                if path in new_paths:
                    old_path_item = old_paths[path]
                    new_path_item = new_paths[path]
                    
                    for method in old_path_item.keys():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                            if method in new_path_item:
                                old_operation = old_path_item[method]
                                new_operation = new_path_item[method]
                                
                                # Compare operation details
                                if self._operations_differ(old_operation, new_operation):
                                    comparison['modified_endpoints'].append({
                                        'path': path,
                                        'method': method.upper(),
                                        'operation_id': new_operation.get('operationId'),
                                        'changes': self._compare_operations(old_operation, new_operation)
                                    })
                                    comparison['change_types'].append('endpoint_modified')
                                    comparison['has_changes'] = True
            
            # Generate summary
            comparison['summary'] = {
                'total_changes': len(comparison['change_types']),
                'endpoints_added': len(comparison['added_endpoints']),
                'endpoints_removed': len(comparison['removed_endpoints']),
                'endpoints_modified': len(comparison['modified_endpoints']),
                'has_version_change': 'version_change' in comparison['change_types']
            }
            
            logger.info(f"Definition comparison completed: {comparison['summary']}")
            
        except Exception as e:
            logger.error(f"Error comparing definitions: {e}")
            comparison['error'] = str(e)
        
        return comparison
    
    def _operations_differ(self, old_op: Dict, new_op: Dict) -> bool:
        """Check if two operations differ significantly"""
        # Compare key fields that matter for security scanning
        key_fields = ['parameters', 'requestBody', 'responses', 'summary', 'description']
        
        for field in key_fields:
            if old_op.get(field) != new_op.get(field):
                return True
        
        return False
    
    def _compare_operations(self, old_op: Dict, new_op: Dict) -> Dict:
        """Compare two operations and return detailed differences"""
        changes = {
            'parameters_changed': False,
            'request_body_changed': False,
            'responses_changed': False,
            'summary_changed': False,
            'description_changed': False
        }
        
        if old_op.get('parameters') != new_op.get('parameters'):
            changes['parameters_changed'] = True
        
        if old_op.get('requestBody') != new_op.get('requestBody'):
            changes['request_body_changed'] = True
        
        if old_op.get('responses') != new_op.get('responses'):
            changes['responses_changed'] = True
        
        if old_op.get('summary') != new_op.get('summary'):
            changes['summary_changed'] = True
        
        if old_op.get('description') != new_op.get('description'):
            changes['description_changed'] = True
        
        return changes
    
    def check_and_trigger_scans(self, service_id: int, new_spec: Dict) -> Dict:
        """
        Check for API definition changes and trigger scans if needed
        
        Args:
            service_id: ID of the service
            new_spec: New API specification
            
        Returns:
            Dictionary with scan trigger results
        """
        results = {
            'scans_triggered': 0,
            'changes_detected': False,
            'comparison_result': None,
            'scan_ids': []
        }
        
        try:
            # Get the service
            service = Service.query.get(service_id)
            if not service:
                logger.error(f"Service {service_id} not found")
                return results
            
            # Get the latest API version
            latest_version = ApiVersion.query.filter_by(
                service_id=service_id
            ).order_by(ApiVersion.created_at.desc()).first()
            
            if not latest_version:
                logger.info(f"No existing API version found for service {service.name}, triggering initial scan")
                results['changes_detected'] = True
                results['comparison_result'] = {'has_changes': True, 'change_types': ['initial_scan']}
            else:
                # Compare with existing version
                old_spec = latest_version.spec_json
                comparison = self.compare_definitions(old_spec, new_spec)
                results['comparison_result'] = comparison
                results['changes_detected'] = comparison['has_changes']
                
                if not comparison['has_changes']:
                    logger.info(f"No changes detected for service {service.name}")
                    return results
            
            # Trigger scans based on change types
            scan_types = self._determine_scan_types(results['comparison_result'])
            
            # Get all endpoints for this service
            endpoints = Endpoint.query.filter_by(service_id=service_id).all()
            
            if not endpoints:
                logger.warning(f"No endpoints found for service {service.name}")
                return results
            
            for scan_type in scan_types:
                for endpoint in endpoints:
                    try:
                        # Create scan record for each endpoint
                        scan = Scan(
                            endpoint_id=endpoint.id,
                            scan_type=scan_type,
                            status='pending',
                            scan_time=datetime.now(timezone.utc)
                        )
                        db.session.add(scan)
                        db.session.flush()
                        
                        # Queue the scan task (import here to avoid circular import)
                        from app.tasks import scan_endpoint
                        task = scan_endpoint.delay(scan.id, {'tools': ['zap', 'nuclei'], 'auto_triggered': True})
                        scan.celery_task_id = task.id
                        
                        results['scans_triggered'] += 1
                        results['scan_ids'].append(scan.id)
                        
                        logger.info(f"Triggered {scan_type} scan for endpoint {endpoint.path} ({endpoint.method}) in service {service.name} (Scan ID: {scan.id})")
                        
                    except Exception as e:
                        logger.error(f"Failed to trigger {scan_type} scan for endpoint {endpoint.path} in service {service.name}: {e}")
            
            # Commit scan records
            db.session.commit()
            
        except Exception as e:
            logger.error(f"Error in check_and_trigger_scans: {e}")
            db.session.rollback()
            results['error'] = str(e)
        
        return results
    
    def _determine_scan_types(self, comparison_result: Dict) -> List[str]:
        """
        Determine which scan types to run based on the changes detected
        
        Args:
            comparison_result: Result from definition comparison
            
        Returns:
            List of scan types to run
        """
        scan_types = []
        change_types = comparison_result.get('change_types', [])
        
        # Always run basic scan for any changes
        scan_types.append('basic')
        
        # Run enhanced scan for significant changes
        significant_changes = [
            'endpoint_added',
            'endpoint_removed',
            'endpoint_modified',
            'version_change'
        ]
        
        if any(change in change_types for change in significant_changes):
            scan_types.append('enhanced')
        
        # Run comprehensive scan for major changes
        major_changes = [
            'version_change',
            'endpoint_added'
        ]
        
        if any(change in change_types for change in major_changes):
            scan_types.append('comprehensive')
        
        return scan_types
    
    def update_service_with_comparison(self, service_id: int, new_spec: Dict) -> Dict:
        """
        Update service with new API definition and trigger scans if changes detected
        
        Args:
            service_id: ID of the service
            new_spec: New API specification
            
        Returns:
            Dictionary with update and scan results
        """
        results = {
            'definition_updated': False,
            'scans_triggered': 0,
            'changes_detected': False,
            'comparison_result': None,
            'scan_ids': []
        }
        
        try:
            # Check for changes and trigger scans
            scan_results = self.check_and_trigger_scans(service_id, new_spec)
            results.update(scan_results)
            
            # Update the API version if there are changes
            if results['changes_detected']:
                service = Service.query.get(service_id)
                if service:
                    # Create new API version
                    version_number = new_spec.get('info', {}).get('version', '1.0.0')
                    api_version = ApiVersion(
                        service_id=service_id,
                        version_number=version_number,
                        spec_json=new_spec
                    )
                    db.session.add(api_version)
                    db.session.flush()
                    
                    # Update endpoints
                    endpoints_added = self._update_endpoints(api_version, new_spec)
                    
                    # Update service last checked
                    service.last_checked = datetime.now(timezone.utc)
                    service.status = 'active'
                    
                    db.session.commit()
                    results['definition_updated'] = True
                    
                    logger.info(f"Updated API definition for service {service.name}, added {endpoints_added} endpoints")
            
        except Exception as e:
            logger.error(f"Error updating service with comparison: {e}")
            db.session.rollback()
            results['error'] = str(e)
        
        return results
    
    def _update_endpoints(self, api_version: ApiVersion, spec: Dict) -> int:
        """
        Update endpoints for the API version
        
        Args:
            api_version: API version instance
            spec: OpenAPI specification
            
        Returns:
            Number of endpoints added/updated
        """
        endpoints_updated = 0
        paths = spec.get('paths', {})
        
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    try:
                        # Check if endpoint exists
                        existing_endpoint = Endpoint.query.filter_by(
                            service_id=api_version.service_id,
                            path=path,
                            method=method.upper()
                        ).first()
                        
                        if existing_endpoint:
                            # Update existing endpoint
                            existing_endpoint.api_version_id = api_version.id
                            existing_endpoint.parameters_schema = operation.get('parameters')
                            existing_endpoint.request_body_schema = operation.get('requestBody')
                            existing_endpoint.response_schema = operation.get('responses')
                            existing_endpoint.updated_at = datetime.now(timezone.utc)
                        else:
                            # Create new endpoint
                            endpoint = Endpoint(
                                service_id=api_version.service_id,
                                api_version_id=api_version.id,
                                path=path,
                                method=method.upper(),
                                operation_id=operation.get('operationId'),
                                summary=operation.get('summary'),
                                description=operation.get('description'),
                                parameters_schema=operation.get('parameters'),
                                request_body_schema=operation.get('requestBody'),
                                response_schema=operation.get('responses')
                            )
                            db.session.add(endpoint)
                        
                        endpoints_updated += 1
                        
                    except Exception as e:
                        logger.warning(f"Failed to update endpoint {method} {path}: {e}")
        
        return endpoints_updated
