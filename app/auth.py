"""
Authentication module for Flask-Login integration
"""

from flask_login import UserMixin
from app.models import User
import bcrypt
from datetime import datetime, timezone
from app import db

class AuthUser(UserMixin):
    """Authentication user class for Flask-Login"""
    
    def __init__(self, user):
        self.user = user
        self.id = user.id
        self.username = user.username
        self.email = user.email
        self.role = user.role
        self._is_active = user.is_active
    
    def get_id(self):
        return self.id
    
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_anonymous(self):
        return False
    
    @property
    def is_active(self):
        return self._is_active

def load_user(user_id):
    """Load user for Flask-Login"""
    user = User.query.get(user_id)
    if user:
        return AuthUser(user)
    return None

def authenticate_user(username, password):
    """Authenticate user with username and password"""
    user = User.query.filter_by(username=username).first()
    
    if user and user.is_active:
        # Check password
        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            # Update last login
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            return AuthUser(user)
    
    return None

def create_user(username, password, email=None, role='user'):
    """Create a new user"""
    # Check if user already exists
    if User.query.filter_by(username=username).first():
        return None
    
    # Hash password
    password_hash = bcrypt.hashpw(
        password.encode('utf-8'), 
        bcrypt.gensalt()
    ).decode('utf-8')
    
    # Create user
    user = User(
        username=username,
        password_hash=password_hash,
        email=email,
        role=role,
        is_active=True
    )
    
    db.session.add(user)
    db.session.commit()
    
    return AuthUser(user)

def change_password(user_id, new_password):
    """Change user password"""
    user = User.query.get(user_id)
    if not user:
        return False
    
    # Hash new password
    password_hash = bcrypt.hashpw(
        new_password.encode('utf-8'), 
        bcrypt.gensalt()
    ).decode('utf-8')
    
    user.password_hash = password_hash
    user.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    
    return True
