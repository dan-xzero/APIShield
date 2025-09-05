#!/usr/bin/env python3
"""
Secure Admin User Setup Script for APIShield
This script creates the initial admin user with a secure password.
"""

import os
import sys
import getpass
import re
from datetime import datetime, timezone

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app import create_app, db
from app.models import User
from app.auth import create_user

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

def setup_admin_user():
    """Setup admin user with secure password"""
    print("🔐 APIShield Admin User Setup")
    print("=" * 40)
    
    # Create Flask app context
    app = create_app()
    
    with app.app_context():
        # Check if admin user already exists
        existing_admin = User.query.filter_by(username='admin').first()
        if existing_admin:
            print("⚠️  Admin user already exists!")
            choice = input("Do you want to reset the admin password? (y/N): ").lower()
            if choice != 'y':
                print("❌ Setup cancelled.")
                return False
            
            # Remove existing admin user
            db.session.delete(existing_admin)
            db.session.commit()
            print("✅ Existing admin user removed.")
        
        # Get admin credentials
        print("\n📝 Please provide admin credentials:")
        
        username = input("Username [admin]: ").strip() or 'admin'
        
        while True:
            password = getpass.getpass("Password: ")
            if not password:
                print("❌ Password cannot be empty!")
                continue
            
            is_valid, message = validate_password(password)
            if is_valid:
                break
            else:
                print(f"❌ {message}")
                print("💡 Password requirements:")
                print("   - At least 8 characters")
                print("   - At least one uppercase letter")
                print("   - At least one lowercase letter")
                print("   - At least one digit")
                print("   - At least one special character")
        
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            print("❌ Passwords do not match!")
            return False
        
        email = input("Email (optional): ").strip() or None
        
        # Create admin user
        try:
            admin_user = create_user(
                username=username,
                password=password,
                email=email,
                role='admin'
            )
            
            if admin_user:
                print(f"\n✅ Admin user '{username}' created successfully!")
                print("🔒 Password has been securely hashed and stored.")
                print("\n📋 Next steps:")
                print("1. Set the ADMIN_PASSWORD environment variable:")
                print(f"   export ADMIN_PASSWORD='{password}'")
                print("2. Or create a .env file with:")
                print(f"   ADMIN_PASSWORD={password}")
                print("3. Restart the application")
                print("\n⚠️  Important: Keep your password secure and never share it!")
                return True
            else:
                print("❌ Failed to create admin user!")
                return False
                
        except Exception as e:
            print(f"❌ Error creating admin user: {e}")
            return False

def main():
    """Main function"""
    try:
        success = setup_admin_user()
        if success:
            print("\n🎉 Admin user setup completed successfully!")
            sys.exit(0)
        else:
            print("\n💥 Admin user setup failed!")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n❌ Setup cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
