"""
APIShield Universal Template System

This module provides universal security testing templates that work for all APIs
regardless of method, parameters, or implementation.
"""

import os
from typing import Dict, List, Any, Optional
from pathlib import Path

# Template categories
TEMPLATE_CATEGORIES = {
    'authentication': 'Authentication Bypass Templates',
    'authorization': 'Authorization Bypass Templates', 
    'input_validation': 'Input Validation Templates',
    'error_handling': 'Error Handling Templates',
    'rate_limiting': 'Rate Limiting Templates',
    'security_headers': 'Security Headers Templates',
    'business_logic': 'Business Logic Templates',
    'injection_attacks': 'Injection Attack Templates',
    'api_specific': 'API-Specific Templates',
    'owasp_top10': 'OWASP API Security Top 10 Templates'
}

# Template severity levels
SEVERITY_LEVELS = {
    'info': 'Informational',
    'low': 'Low Risk',
    'medium': 'Medium Risk', 
    'high': 'High Risk',
    'critical': 'Critical Risk'
}

# Template tags for categorization
TEMPLATE_TAGS = {
    'api': 'API Security',
    'rest': 'REST API',
    'graphql': 'GraphQL',
    'soap': 'SOAP API',
    'authentication': 'Authentication',
    'authorization': 'Authorization',
    'injection': 'Injection',
    'xss': 'Cross-Site Scripting',
    'sql': 'SQL Injection',
    'nosql': 'NoSQL Injection',
    'ssrf': 'Server-Side Request Forgery',
    'xxe': 'XML External Entity',
    'rce': 'Remote Code Execution',
    'lfi': 'Local File Inclusion',
    'rfi': 'Remote File Inclusion',
    'csrf': 'Cross-Site Request Forgery',
    'cors': 'Cross-Origin Resource Sharing',
    'jwt': 'JSON Web Token',
    'oauth': 'OAuth',
    'rate_limit': 'Rate Limiting',
    'dos': 'Denial of Service',
    'business_logic': 'Business Logic',
    'misconfiguration': 'Misconfiguration',
    'information_disclosure': 'Information Disclosure'
}

def get_template_dir() -> Path:
    """Get the templates directory path"""
    return Path(__file__).parent

def get_universal_templates_dir() -> Path:
    """Get the universal templates directory path"""
    return get_template_dir() / 'universal'

def get_custom_templates_dir() -> Path:
    """Get the custom templates directory path"""
    return get_template_dir() / 'custom'

def get_community_templates_dir() -> Path:
    """Get the community templates directory path"""
    return get_template_dir() / 'community'

def ensure_template_directories():
    """Ensure all template directories exist"""
    directories = [
        get_universal_templates_dir(),
        get_custom_templates_dir(), 
        get_community_templates_dir()
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
