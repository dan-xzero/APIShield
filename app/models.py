"""
Database models for the API Security Scan Framework
"""

from datetime import datetime, timezone
from sqlalchemy import JSON, Text
from sqlalchemy.dialects.postgresql import UUID
from app import db
import uuid

def generate_uuid():
    """Generate a UUID for primary keys"""
    return str(uuid.uuid4())

class Service(db.Model):
    """API Service model"""
    __tablename__ = 'services'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    name = db.Column(db.String(255), nullable=False, unique=True)
    api_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), default='active')  # active, inactive, error
    last_checked = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    api_versions = db.relationship('ApiVersion', backref='service', lazy='dynamic', cascade='all, delete-orphan')
    endpoints = db.relationship('Endpoint', backref='service', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Service {self.name}>'

class ApiVersion(db.Model):
    """API Version model for storing OpenAPI specifications"""
    __tablename__ = 'api_versions'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    service_id = db.Column(db.String(36), db.ForeignKey('services.id'), nullable=False)
    version_number = db.Column(db.String(50), nullable=False)
    spec_json = db.Column(JSON, nullable=False)  # Raw OpenAPI specification
    fetched_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    endpoints = db.relationship('Endpoint', backref='api_version', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<ApiVersion {self.service.name} v{self.version_number}>'

class Endpoint(db.Model):
    """API Endpoint model"""
    __tablename__ = 'endpoints'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    service_id = db.Column(db.String(36), db.ForeignKey('services.id'), nullable=False)
    api_version_id = db.Column(db.String(36), db.ForeignKey('api_versions.id'), nullable=False)
    path = db.Column(db.String(500), nullable=False)
    method = db.Column(db.String(10), nullable=False)  # GET, POST, PUT, DELETE, etc.
    operation_id = db.Column(db.String(255))
    summary = db.Column(Text)
    description = db.Column(Text)
    parameters_schema = db.Column(JSON)  # OpenAPI parameters definition
    request_body_schema = db.Column(JSON)  # OpenAPI request body definition
    response_schema = db.Column(JSON)  # OpenAPI response definition
    param_values = db.Column(JSON)  # Last successful parameter set used in scans
    mutation_strategy = db.Column(JSON)  # Parameter mutation strategy
    risk_score = db.Column(db.Float, default=0.0)  # Calculated risk score
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    scans = db.relationship('Scan', backref='endpoint', lazy='dynamic', cascade='all, delete-orphan')
    
    @property
    def parsed_parameters_schema(self):
        """Parse parameters_schema from JSON string to Python object"""
        if self.parameters_schema:
            if isinstance(self.parameters_schema, str):
                try:
                    import json
                    return json.loads(self.parameters_schema)
                except (json.JSONDecodeError, TypeError):
                    return []
            elif isinstance(self.parameters_schema, list):
                return self.parameters_schema
            else:
                return []
        return []
    
    def __repr__(self):
        return f'<Endpoint {self.method} {self.path}>'

class Scan(db.Model):
    """Security Scan model"""
    __tablename__ = 'scans'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    endpoint_id = db.Column(db.String(36), db.ForeignKey('endpoints.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # zap, sqlmap, ssrfmap, xsstrike, combined
    status = db.Column(db.String(50), default='pending')  # pending, running, completed, failed
    scan_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime)
    duration = db.Column(db.Integer)  # Duration in seconds
    param_values_used = db.Column(JSON)  # Parameter set employed for this run
    tools_used = db.Column(JSON)  # List of tools used in this scan
    scan_config = db.Column(JSON)  # Scan configuration used
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Scan {self.scan_type} on {self.endpoint.path}>'

class ParameterSet(db.Model):
    """Parameter Set model for storing successful parameter combinations"""
    __tablename__ = 'parameter_sets'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    endpoint_id = db.Column(db.String(36), db.ForeignKey('endpoints.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)  # Human-readable name
    description = db.Column(Text)  # Description of this parameter set
    parameters = db.Column(JSON, nullable=False)  # Parameter values
    request_body = db.Column(JSON)  # Request body if applicable
    response_status = db.Column(db.Integer)  # HTTP status code of successful response
    response_body = db.Column(Text)  # Response body (truncated if too large)
    response_headers = db.Column(JSON)  # Response headers
    is_valid = db.Column(db.Boolean, default=True)  # Whether this parameter set is still valid
    success_count = db.Column(db.Integer, default=1)  # Number of successful uses
    last_used = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    endpoint = db.relationship('Endpoint', backref='parameter_sets')
    
    def __repr__(self):
        return f'<ParameterSet {self.name} for {self.endpoint.path}>'

class ParameterMutation(db.Model):
    """Parameter Mutation model for tracking parameter variations"""
    __tablename__ = 'parameter_mutations'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    parameter_set_id = db.Column(db.String(36), db.ForeignKey('parameter_sets.id'), nullable=False)
    mutation_type = db.Column(db.String(50), nullable=False)  # boundary, fuzz, sql_injection, xss, etc.
    original_value = db.Column(Text)  # Original parameter value
    mutated_value = db.Column(Text)  # Mutated parameter value
    success = db.Column(db.Boolean)  # Whether mutation was successful
    vulnerability_found = db.Column(db.Boolean, default=False)  # Whether vulnerability was found
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    parameter_set = db.relationship('ParameterSet', backref='mutations')
    
    def __repr__(self):
        return f'<ParameterMutation {self.mutation_type} on {self.parameter_set.name}>'

class Vulnerability(db.Model):
    """Vulnerability model with duplicate prevention"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    scan_id = db.Column(db.String(36), db.ForeignKey('scans.id'), nullable=False)
    endpoint_id = db.Column(db.String(36), db.ForeignKey('endpoints.id'), nullable=False)  # Direct reference to endpoint
    service_id = db.Column(db.String(36), db.ForeignKey('services.id'), nullable=False)  # Direct reference to service
    
    # Core vulnerability fields
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(Text)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low, info
    cvss_score = db.Column(db.Float)
    risk_score = db.Column(db.Float, default=0.0)  # Custom risk score
    category = db.Column(db.String(100))  # sql_injection, xss, ssrf, etc.
    details = db.Column(JSON)  # Detailed vulnerability information
    evidence = db.Column(Text)  # Evidence of the vulnerability
    
    # Duplicate prevention fields
    vulnerability_hash = db.Column(db.String(64), nullable=False)  # Hash to identify duplicates
    tool_used = db.Column(db.String(50))  # Which tool found this vulnerability
    
    # Status fields
    false_positive = db.Column(db.Boolean, default=False)
    remediated = db.Column(db.Boolean, default=False)
    remediated_at = db.Column(db.DateTime)
    
    # Tracking fields
    first_seen_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))  # When first discovered
    last_seen_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))  # When last seen
    occurrence_count = db.Column(db.Integer, default=1)  # How many times this vulnerability was found
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # AI Validation fields
    ai_confidence = db.Column(db.String(50), nullable=True)
    ai_analysis = db.Column(Text, nullable=True)
    
    # Relationships
    endpoint = db.relationship('Endpoint', backref='vulnerabilities')
    service = db.relationship('Service', backref='vulnerabilities')
    
    def __repr__(self):
        return f'<Vulnerability {self.name} ({self.severity}) on {self.endpoint.path if self.endpoint else "Unknown"}>'
    
    @staticmethod
    def generate_vulnerability_hash(endpoint_id, name, category, evidence):
        """Generate a unique hash for vulnerability identification"""
        import hashlib
        hash_data = f"{endpoint_id}:{name}:{category}:{evidence}"
        return hashlib.md5(hash_data.encode()).hexdigest()
    
    @staticmethod
    def find_or_create_vulnerability(scan_id, endpoint_id, service_id, name, description, 
                                   severity, category, details, evidence, tool_used, **kwargs):
        """Find existing vulnerability or create new one, preventing duplicates"""
        from app import db
        
        # Generate vulnerability hash
        vuln_hash = Vulnerability.generate_vulnerability_hash(endpoint_id, name, category, evidence)
        
        # Check if vulnerability already exists
        existing_vuln = Vulnerability.query.filter_by(
            vulnerability_hash=vuln_hash,
            endpoint_id=endpoint_id
        ).first()
        
        if existing_vuln:
            # Update existing vulnerability
            existing_vuln.last_seen_at = datetime.now(timezone.utc)
            existing_vuln.occurrence_count += 1
            existing_vuln.updated_at = datetime.now(timezone.utc)

            # If new AI analysis is provided, update it
            if 'ai_analysis' in kwargs and kwargs['ai_analysis']:
                existing_vuln.ai_analysis = kwargs['ai_analysis']
            if 'ai_confidence' in kwargs and kwargs['ai_confidence']:
                existing_vuln.ai_confidence = kwargs['ai_confidence']
            
            # Update scan reference (create new scan-vulnerability relationship)
            # Note: We keep the original vulnerability but track new occurrences
            
            db.session.commit()
            return existing_vuln, False  # False = not new
        else:
            # Create new vulnerability
            new_vuln = Vulnerability(
                scan_id=scan_id,
                endpoint_id=endpoint_id,
                service_id=service_id,
                name=name,
                description=description,
                severity=severity,
                category=category,
                details=details,
                evidence=evidence,
                tool_used=tool_used,
                vulnerability_hash=vuln_hash,
                first_seen_at=datetime.now(timezone.utc),
                last_seen_at=datetime.now(timezone.utc),
                occurrence_count=1,
                ai_confidence=kwargs.get('ai_confidence'),
                ai_analysis=kwargs.get('ai_analysis'),
                **kwargs
            )
            
            db.session.add(new_vuln)
            db.session.commit()
            return new_vuln, True  # True = new vulnerability
    
    def __repr__(self):
        return f'<Vulnerability {self.name} ({self.severity})>'

class ScanTarget(db.Model):
    """Scan Target model for tracking endpoints that need scanning"""
    __tablename__ = 'scan_targets'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    service_id = db.Column(db.String(36), db.ForeignKey('services.id'), nullable=False)
    api_version_id = db.Column(db.String(36), db.ForeignKey('api_versions.id'), nullable=False)
    endpoint_id = db.Column(db.String(36), db.ForeignKey('endpoints.id'), nullable=False)
    path = db.Column(db.String(500), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    param_profile = db.Column(JSON)  # Parameter profile for tool selection
    change_type = db.Column(db.String(20))  # added, modified, removed
    priority = db.Column(db.Integer, default=1)  # 1=low, 2=medium, 3=high, 4=critical
    scheduled_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    service = db.relationship('Service', backref='scan_targets')
    api_version = db.relationship('ApiVersion', backref='scan_targets')
    endpoint = db.relationship('Endpoint', backref='scan_targets')
    
    def __repr__(self):
        return f'<ScanTarget {self.method} {self.path}>'

class User(db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True)
    role = db.Column(db.String(20), default='user')  # admin, user, viewer
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<User {self.username}>'

class ScanSchedule(db.Model):
    """Scan Schedule model for recurring scans"""
    __tablename__ = 'scan_schedules'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    service_id = db.Column(db.String(36), db.ForeignKey('services.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    cron_expression = db.Column(db.String(100), nullable=False)  # Cron expression for scheduling
    scan_type = db.Column(db.String(50), default='combined')
    is_active = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime)
    next_run = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    service = db.relationship('Service', backref='scan_schedules')
    
    def __repr__(self):
        return f'<ScanSchedule {self.name} for {self.service.name}>'
