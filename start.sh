#!/bin/bash

# API Security Scanner Framework - Startup Script

echo "🚀 Starting API Security Scanner Framework..."

# Check if Python is available
if ! command -v python &> /dev/null; then
    echo "❌ Python is not installed or not in PATH"
    exit 1
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Creating from template..."
    cp env.example .env
    echo "📝 Please edit .env file with your configuration before running again."
    exit 1
fi

# Set default port if not specified
export FLASK_PORT=${FLASK_PORT:-5001}

echo "🔧 Configuration:"
echo "   - Port: $FLASK_PORT"
echo "   - Database: SQLite (api_scanner.db)"
echo "   - Admin credentials: admin/secure_password_change_this"

# Start the application
echo "🌐 Starting Flask application on port $FLASK_PORT..."
echo "📊 Dashboard will be available at: http://localhost:$FLASK_PORT"
echo "🔑 Login with: admin / secure_password_change_this"
echo ""
echo "Press Ctrl+C to stop the application"
echo ""

python run.py
