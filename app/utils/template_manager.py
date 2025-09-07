"""
APIShield Template Manager

Manages universal security testing templates for API security scanning.
Provides template loading, validation, and management capabilities.
"""

import os
import yaml
import json
import logging
import tempfile
import uuid
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from datetime import datetime
from app.config import Config

logger = logging.getLogger(__name__)

class APIShieldTemplateManager:
    """Manages universal security testing templates"""
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent.parent / 'templates'
        self.universal_dir = self.templates_dir / 'universal'
        self.custom_dir = self.templates_dir / 'custom'
        self.community_dir = self.templates_dir / 'community'
        
        # Ensure directories exist
        self._ensure_directories()
        
        # Template cache
        self._template_cache = {}
        self._cache_ttl = 300  # 5 minutes
        
    def _ensure_directories(self):
        """Ensure all template directories exist"""
        for directory in [self.templates_dir, self.universal_dir, self.custom_dir, self.community_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def create_universal_templates(self):
        """Create universal security testing templates"""
        logger.info("🔧 Creating universal security testing templates...")
        
        templates = {
            'authentication_bypass.yaml': self._create_authentication_bypass_template(),
            'authorization_bypass.yaml': self._create_authorization_bypass_template(),
            'input_validation.yaml': self._create_input_validation_template(),
            'error_handling.yaml': self._create_error_handling_template(),
            'rate_limiting.yaml': self._create_rate_limiting_template(),
            'security_headers.yaml': self._create_security_headers_template(),
            'business_logic.yaml': self._create_business_logic_template(),
            'injection_attacks.yaml': self._create_injection_attacks_template(),
            'api_specific.yaml': self._create_api_specific_template(),
            'owasp_top10.yaml': self._create_owasp_top10_template()
        }
        
        for filename, content in templates.items():
            template_path = self.universal_dir / filename
            with open(template_path, 'w') as f:
                f.write(content)
            logger.info(f"✅ Created template: {filename}")
        
        logger.info(f"🎯 Created {len(templates)} universal templates")
    
    def _create_authentication_bypass_template(self) -> str:
        """Create authentication bypass template"""
        return """id: auth-bypass-universal
info:
  name: Authentication Bypass - Universal
  author: APIShield
  severity: high
  description: Tests for authentication bypass vulnerabilities in APIs
  tags: api,authentication,auth-bypass,security
  reference:
    - https://owasp.org/www-project-api-security/
    - https://owasp.org/www-community/attacks/Authentication_Bypass

requests:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "unauthorized"
          - "forbidden"
          - "access denied"
          - "authentication required"
        condition: and
        part: body
      - type: status
        status:
          - 401
          - 403
        condition: and
      - type: word
        words:
          - "token"
          - "jwt"
          - "bearer"
          - "session"
        condition: and
        part: header
        negative: true

  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "username": "admin",
        "password": "admin"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "success"
          - "authenticated"
          - "token"
          - "jwt"
        condition: and
        part: body
      - type: status
        status:
          - 200
          - 201
        condition: and

  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Authorization: "Bearer invalid-token"
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "invalid"
          - "expired"
          - "malformed"
        condition: and
        part: body
        negative: true
      - type: status
        status:
          - 200
          - 201
        condition: and
"""
    
    def _create_authorization_bypass_template(self) -> str:
        """Create authorization bypass template"""
        return """id: authz-bypass-universal
info:
  name: Authorization Bypass - Universal
  author: APIShield
  severity: high
  description: Tests for authorization bypass vulnerabilities in APIs
  tags: api,authorization,authz-bypass,security,idor
  reference:
    - https://owasp.org/www-project-api-security/
    - https://owasp.org/www-community/attacks/Insecure_Direct_Object_References

requests:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "forbidden"
          - "access denied"
          - "unauthorized"
        condition: and
        part: body
        negative: true
      - type: status
        status:
          - 200
          - 201
        condition: and

  - method: PUT
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "id": "1",
        "role": "admin",
        "permissions": ["read", "write", "delete"]
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "success"
          - "updated"
          - "modified"
        condition: and
        part: body
      - type: status
        status:
          - 200
          - 201
        condition: and

  - method: DELETE
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "deleted"
          - "removed"
          - "success"
        condition: and
        part: body
      - type: status
        status:
          - 200
          - 204
        condition: and
"""
    
    def _create_input_validation_template(self) -> str:
        """Create input validation template"""
        return """id: input-validation-universal
info:
  name: Input Validation - Universal
  author: APIShield
  severity: medium
  description: Tests for input validation vulnerabilities in APIs
  tags: api,input-validation,sql-injection,xss,injection
  reference:
    - https://owasp.org/www-project-api-security/
    - https://owasp.org/www-community/attacks/SQL_Injection

requests:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "sql"
          - "mysql"
          - "postgresql"
          - "oracle"
          - "syntax error"
          - "sql error"
        condition: and
        part: body
      - type: status
        status:
          - 500
          - 502
          - 503
        condition: and

  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "query": "'; DROP TABLE users; --",
        "search": "<script>alert('xss')</script>",
        "input": "{{randstr}}"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "error"
          - "exception"
          - "invalid"
          - "malformed"
        condition: and
        part: body
        negative: true
      - type: status
        status:
          - 200
          - 201
        condition: and

  - method: PUT
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "data": "{{randstr}}",
        "length": "999999999",
        "size": "-1"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "overflow"
          - "too large"
          - "invalid size"
        condition: and
        part: body
      - type: status
        status:
          - 400
          - 413
          - 500
        condition: and
"""
    
    def _create_error_handling_template(self) -> str:
        """Create error handling template"""
        return """id: error-handling-universal
info:
  name: Error Handling - Universal
  author: APIShield
  severity: medium
  description: Tests for error handling and information disclosure vulnerabilities
  tags: api,error-handling,information-disclosure,security
  reference:
    - https://owasp.org/www-project-api-security/
    - https://owasp.org/www-community/attacks/Information_disclosure

requests:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "stack trace"
          - "exception"
          - "error at line"
          - "file:"
          - "path:"
        condition: and
        part: body
      - type: word
        words:
          - "database"
          - "connection"
          - "sql"
          - "mysql"
          - "postgresql"
        condition: and
        part: body

  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "invalid": "{{randstr}}"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "debug"
          - "trace"
          - "verbose"
        condition: and
        part: body
      - type: word
        words:
          - "internal"
          - "server"
          - "error"
        condition: and
        part: body

  - method: GET
    path:
      - "{{BaseURL}}/{{path}}/nonexistent"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "not found"
          - "404"
          - "missing"
        condition: and
        part: body
        negative: true
      - type: status
        status:
          - 200
          - 201
        condition: and
"""
    
    def _create_rate_limiting_template(self) -> str:
        """Create rate limiting template"""
        return """id: rate-limiting-universal
info:
  name: Rate Limiting - Universal
  author: APIShield
  severity: medium
  description: Tests for rate limiting and DoS protection vulnerabilities
  tags: api,rate-limiting,dos,security
  reference:
    - https://owasp.org/www-project-api-security/
    - https://owasp.org/www-community/attacks/Denial_of_Service

requests:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "rate limit"
          - "too many requests"
          - "quota exceeded"
        condition: and
        part: body
        negative: true
      - type: status
        status:
          - 200
          - 201
        condition: and

  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "data": "{{randstr}}"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "429"
          - "rate limit"
          - "throttle"
        condition: and
        part: body
        negative: true
      - type: status
        status:
          - 200
          - 201
        condition: and

  - method: PUT
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "large_data": "{{randstr(10000)}}"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "payload too large"
          - "request too large"
          - "413"
        condition: and
        part: body
        negative: true
      - type: status
        status:
          - 200
          - 201
        condition: and
"""
    
    def _create_security_headers_template(self) -> str:
        """Create security headers template"""
        return """id: security-headers-universal
info:
  name: Security Headers - Universal
  author: APIShield
  severity: low
  description: Tests for missing security headers in API responses
  tags: api,security-headers,misconfiguration,security
  reference:
    - https://owasp.org/www-project-api-security/
    - https://owasp.org/www-community/attacks/Clickjacking

requests:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "X-Frame-Options"
          - "X-Content-Type-Options"
          - "X-XSS-Protection"
          - "Strict-Transport-Security"
          - "Content-Security-Policy"
        condition: and
        part: header
        negative: true
      - type: word
        words:
          - "X-Frame-Options: DENY"
          - "X-Frame-Options: SAMEORIGIN"
        condition: and
        part: header
        negative: true

  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "test": "{{randstr}}"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "X-Content-Type-Options: nosniff"
        condition: and
        part: header
        negative: true
      - type: word
        words:
          - "X-XSS-Protection: 1; mode=block"
        condition: and
        part: header
        negative: true
"""
    
    def _create_business_logic_template(self) -> str:
        """Create business logic template"""
        return """id: business-logic-universal
info:
  name: Business Logic - Universal
  author: APIShield
  severity: high
  description: Tests for business logic vulnerabilities in APIs
  tags: api,business-logic,security,logic-flaw
  reference:
    - https://owasp.org/www-project-api-security/
    - https://owasp.org/www-community/attacks/Business_Logic_Vulnerabilities

requests:
  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "price": "-100",
        "quantity": "999999",
        "discount": "200"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "success"
          - "created"
          - "updated"
        condition: and
        part: body
      - type: status
        status:
          - 200
          - 201
        condition: and

  - method: PUT
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "status": "completed",
        "paid": false,
        "shipped": true
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "success"
          - "updated"
          - "modified"
        condition: and
        part: body
      - type: status
        status:
          - 200
          - 201
        condition: and

  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "user_id": "1",
        "role": "admin",
        "permissions": ["*"]
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "success"
          - "created"
          - "updated"
        condition: and
        part: body
      - type: status
        status:
          - 200
          - 201
        condition: and
"""
    
    def _create_injection_attacks_template(self) -> str:
        """Create injection attacks template"""
        return """id: injection-attacks-universal
info:
  name: Injection Attacks - Universal
  author: APIShield
  severity: high
  description: Tests for various injection attack vulnerabilities
  tags: api,injection,sql-injection,xss,xxe,command-injection
  reference:
    - https://owasp.org/www-project-api-security/
    - https://owasp.org/www-community/attacks/SQL_Injection

requests:
  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "query": "'; DROP TABLE users; --",
        "search": "{{randstr}}"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "sql"
          - "mysql"
          - "postgresql"
          - "oracle"
          - "syntax error"
        condition: and
        part: body
      - type: status
        status:
          - 500
          - 502
          - 503
        condition: and

  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/xml"
      Accept: "application/xml"
    body: |
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
      <data>&xxe;</data>
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "root:"
          - "bin:"
          - "daemon:"
        condition: and
        part: body
      - type: word
        words:
          - "xxe"
          - "xml external entity"
        condition: and
        part: body

  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "command": "ls -la",
        "input": "{{randstr}}"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "total"
          - "drwx"
          - "rwx"
        condition: and
        part: body
      - type: word
        words:
          - "command"
          - "execution"
        condition: and
        part: body
"""
    
    def _create_api_specific_template(self) -> str:
        """Create API-specific template"""
        return """id: api-specific-universal
info:
  name: API Specific - Universal
  author: APIShield
  severity: medium
  description: Tests for API-specific vulnerabilities and misconfigurations
  tags: api,api-security,rest,graphql,soap
  reference:
    - https://owasp.org/www-project-api-security/
    - https://owasp.org/www-community/attacks/API_Security

requests:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "swagger"
          - "openapi"
          - "api-docs"
        condition: and
        part: body
      - type: word
        words:
          - "version"
          - "info"
          - "paths"
        condition: and
        part: body

  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "query": "query { __schema { types { name } } }"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "__schema"
          - "types"
          - "fields"
        condition: and
        part: body
      - type: word
        words:
          - "graphql"
          - "introspection"
        condition: and
        part: body

  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "cors"
          - "cross-origin"
        condition: and
        part: header
      - type: word
        words:
          - "Access-Control-Allow-Origin: *"
        condition: and
        part: header
"""
    
    def _create_owasp_top10_template(self) -> str:
        """Create OWASP API Security Top 10 template"""
        return """id: owasp-top10-universal
info:
  name: OWASP API Security Top 10 - Universal
  author: APIShield
  severity: high
  description: Tests for OWASP API Security Top 10 vulnerabilities
  tags: api,owasp,top10,security
  reference:
    - https://owasp.org/www-project-api-security/
    - https://owasp.org/www-project-top-ten/

requests:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "broken object level authorization"
          - "broken authentication"
          - "excessive data exposure"
        condition: and
        part: body
        negative: true
      - type: status
        status:
          - 200
          - 201
        condition: and

  - method: POST
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "mass assignment": true,
        "admin": true,
        "role": "admin"
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "success"
          - "created"
          - "updated"
        condition: and
        part: body
      - type: status
        status:
          - 200
          - 201
        condition: and

  - method: PUT
    path:
      - "{{BaseURL}}/{{path}}"
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    body: |
      {
        "rate limiting": false,
        "throttling": false,
        "quota": false
      }
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "success"
          - "updated"
          - "modified"
        condition: and
        part: body
      - type: status
        status:
          - 200
          - 201
        condition: and
"""
    
    def load_template(self, template_path: Union[str, Path]) -> Dict[str, Any]:
        """Load a template from file"""
        template_path = Path(template_path)
        
        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")
        
        try:
            with open(template_path, 'r') as f:
                template = yaml.safe_load(f)
            
            # Validate template structure
            self._validate_template(template)
            
            return template
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in template {template_path}: {e}")
    
    def _validate_template(self, template: Dict[str, Any]):
        """Validate template structure"""
        required_fields = ['id', 'info', 'requests']
        
        for field in required_fields:
            if field not in template:
                raise ValueError(f"Template missing required field: {field}")
        
        # Validate info section
        info = template['info']
        required_info_fields = ['name', 'author', 'severity', 'description']
        
        for field in required_info_fields:
            if field not in info:
                raise ValueError(f"Template info missing required field: {field}")
        
        # Validate requests section
        requests = template['requests']
        if not isinstance(requests, list):
            raise ValueError("Template requests must be a list")
        
        for i, request in enumerate(requests):
            if not isinstance(request, dict):
                raise ValueError(f"Request {i} must be a dictionary")
            
            if 'method' not in request:
                raise ValueError(f"Request {i} missing required field: method")
    
    def get_template_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get templates by category"""
        templates = []
        
        # Search in universal templates
        for template_file in self.universal_dir.glob('*.yaml'):
            try:
                template = self.load_template(template_file)
                if category in template.get('info', {}).get('tags', []):
                    templates.append(template)
            except Exception as e:
                logger.warning(f"Failed to load template {template_file}: {e}")
        
        return templates
    
    def create_custom_template(self, template_data: Dict[str, Any]) -> str:
        """Create a custom template"""
        # Generate unique ID
        template_id = f"custom-{uuid.uuid4().hex[:8]}"
        template_data['id'] = template_id
        
        # Validate template
        self._validate_template(template_data)
        
        # Save template
        template_path = self.custom_dir / f"{template_id}.yaml"
        with open(template_path, 'w') as f:
            yaml.dump(template_data, f, default_flow_style=False)
        
        logger.info(f"✅ Created custom template: {template_id}")
        return template_id
    
    def list_templates(self) -> Dict[str, List[str]]:
        """List all available templates"""
        templates = {
            'universal': [],
            'custom': [],
            'community': []
        }
        
        for category, directory in [
            ('universal', self.universal_dir),
            ('custom', self.custom_dir),
            ('community', self.community_dir)
        ]:
            for template_file in directory.glob('*.yaml'):
                templates[category].append(template_file.stem)
        
        return templates
    
    def get_template_info(self, template_id: str) -> Dict[str, Any]:
        """Get template information"""
        # Search in all directories
        for directory in [self.universal_dir, self.custom_dir, self.community_dir]:
            template_file = directory / f"{template_id}.yaml"
            if template_file.exists():
                return self.load_template(template_file)
        
        raise FileNotFoundError(f"Template not found: {template_id}")
    
    def delete_template(self, template_id: str) -> bool:
        """Delete a custom template"""
        template_file = self.custom_dir / f"{template_id}.yaml"
        
        if template_file.exists():
            template_file.unlink()
            logger.info(f"✅ Deleted template: {template_id}")
            return True
        
        return False
    
    def create_endpoint_specific_template(self, endpoint: Dict[str, Any], param_values: Dict[str, Any], auth_headers: Dict[str, str]) -> str:
        """Create an endpoint-specific template"""
        method = endpoint.get('method', 'GET').upper()
        path = endpoint.get('path', '')
        
        # Generate unique template ID
        template_id = f"endpoint-{uuid.uuid4().hex[:8]}"
        
        # Prepare headers
        headers = {}
        if auth_headers:
            headers.update(auth_headers)
        
        # Prepare request body for POST/PUT/PATCH
        body = ""
        if method in ['POST', 'PUT', 'PATCH'] and param_values:
            body = json.dumps(param_values)
        
        # Create template
        template = {
            'id': template_id,
            'info': {
                'name': f'Endpoint Scan - {method} {path}',
                'author': 'APIShield',
                'severity': 'info',
                'description': f'Security scan for {method} {path}',
                'tags': ['api', 'endpoint', method.lower()]
            },
            'requests': [
                {
                    'method': method,
                    'path': [f"{{{{BaseURL}}}}{path}"],
                    'headers': headers,
                    'body': body if body else None,
                    'matchers-condition': 'or',
                    'matchers': [
                        {
                            'type': 'word',
                            'words': ['error', 'exception', 'sql', 'mysql', 'postgresql', 'oracle', 'syntax error', 'stack trace'],
                            'condition': 'or',
                            'part': 'body'
                        },
                        {
                            'type': 'status',
                            'status': [500, 502, 503, 504],
                            'condition': 'or'
                        },
                        {
                            'type': 'regex',
                            'regex': ['(?i)(sql|mysql|postgresql|oracle).*error', '(?i)(syntax|parse).*error'],
                            'condition': 'or',
                            'part': 'body'
                        }
                    ]
                }
            ]
        }
        
        # Remove None values
        if not template['requests'][0]['body']:
            del template['requests'][0]['body']
        
        # Save template
        template_path = self.custom_dir / f"{template_id}.yaml"
        with open(template_path, 'w') as f:
            yaml.dump(template, f, default_flow_style=False)
        
        logger.info(f"✅ Created endpoint-specific template: {template_id}")
        return template_id
    
    def get_template_path(self, template_id: str) -> Optional[Path]:
        """Get the file path for a template"""
        for directory in [self.universal_dir, self.custom_dir, self.community_dir]:
            template_file = directory / f"{template_id}.yaml"
            if template_file.exists():
                return template_file
        
        return None
