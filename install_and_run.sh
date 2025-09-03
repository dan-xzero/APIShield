#!/bin/bash

# APIShield - Complete Install and Run Script
# This script will install all dependencies, set up the environment, and run the application

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}================================${NC}"
    echo -e "${PURPLE}$1${NC}"
    echo -e "${PURPLE}================================${NC}"
}

print_step() {
    echo -e "${CYAN}➤ $1${NC}"
}

# Function to detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            OS="ubuntu"
            PACKAGE_MANAGER="apt"
        elif command -v yum &> /dev/null; then
            OS="centos"
            PACKAGE_MANAGER="yum"
        elif command -v dnf &> /dev/null; then
            OS="fedora"
            PACKAGE_MANAGER="dnf"
        else
            OS="linux"
            PACKAGE_MANAGER="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PACKAGE_MANAGER="brew"
    else
        OS="unknown"
        PACKAGE_MANAGER="unknown"
    fi
    
    print_status "Detected OS: $OS"
    print_status "Package manager: $PACKAGE_MANAGER"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install system dependencies
install_system_deps() {
    print_step "Installing system dependencies..."
    
    case $OS in
        "ubuntu"|"debian")
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv git curl wget unzip default-jre default-jdk
            ;;
        "centos"|"rhel")
            sudo yum update -y
            sudo yum install -y python3 python3-pip git curl wget unzip java-11-openjdk
            ;;
        "fedora")
            sudo dnf update -y
            sudo dnf install -y python3 python3-pip git curl wget unzip java-11-openjdk
            ;;
        "macos")
            if ! command_exists brew; then
                print_status "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew update
            brew install python3 git curl wget unzip openjdk@11
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    print_success "System dependencies installed"
}

# Function to install Python dependencies
install_python_deps() {
    print_step "Setting up Python environment..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_status "Virtual environment created"
    else
        print_status "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install Python packages
    print_status "Installing Python dependencies..."
    pip install -r requirements.txt
    
    print_success "Python dependencies installed"
}

# Function to install OWASP ZAP
install_zap() {
    print_step "Installing OWASP ZAP..."
    
    ZAP_VERSION="2.14.0"
    ZAP_DIR="$HOME/.zap"
    
    # Create ZAP directory
    mkdir -p "$ZAP_DIR"
    
    case $OS in
        "macos")
            ZAP_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_macos.dmg"
            ZAP_DMG="$ZAP_DIR/ZAP_${ZAP_VERSION}_macos.dmg"
            
            if [ ! -f "$ZAP_DMG" ]; then
                print_status "Downloading ZAP for macOS..."
                curl -L -o "$ZAP_DMG" "$ZAP_URL"
            fi
            
            # Mount and install DMG
            print_status "Installing ZAP..."
            hdiutil attach "$ZAP_DMG"
            cp -R "/Volumes/OWASP ZAP $ZAP_VERSION/OWASP ZAP.app" /Applications/
            hdiutil detach "/Volumes/OWASP ZAP $ZAP_VERSION"
            
            # Create symlink for command line access
            ln -sf "/Applications/OWASP ZAP.app/Contents/Java/zap.sh" "$ZAP_DIR/zap.sh"
            ;;
        "ubuntu"|"debian"|"centos"|"rhel"|"fedora")
            ZAP_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"
            ZAP_TAR="$ZAP_DIR/ZAP_${ZAP_VERSION}_Linux.tar.gz"
            
            if [ ! -f "$ZAP_TAR" ]; then
                print_status "Downloading ZAP for Linux..."
                curl -L -o "$ZAP_TAR" "$ZAP_URL"
            fi
            
            cd "$ZAP_DIR"
            tar -xzf "$ZAP_TAR"
            cd ZAP_${ZAP_VERSION}
            
            # Create symlink
            ln -sf "$(pwd)/zap.sh" "$ZAP_DIR/zap.sh"
            cd - > /dev/null
            ;;
    esac
    
    # Test ZAP installation
    if [ -f "$ZAP_DIR/zap.sh" ]; then
        print_success "ZAP installed successfully"
        echo "export ZAP_PATH=$ZAP_DIR/zap.sh" >> ~/.bashrc
        echo "export ZAP_PATH=$ZAP_DIR/zap.sh" >> ~/.zshrc
    else
        print_error "ZAP installation failed"
        exit 1
    fi
}

# Function to install Nuclei
install_nuclei() {
    print_step "Installing Nuclei..."
    
    case $OS in
        "macos")
            brew install nuclei
            ;;
        "ubuntu"|"debian"|"centos"|"rhel"|"fedora")
            # Download latest release
            NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
            NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION:1}_linux_amd64.tar.gz"
            
            curl -L -o /tmp/nuclei.tar.gz "$NUCLEI_URL"
            sudo tar -xzf /tmp/nuclei.tar.gz -C /usr/local/bin nuclei
            sudo chmod +x /usr/local/bin/nuclei
            rm /tmp/nuclei.tar.gz
            ;;
    esac
    
    print_success "Nuclei installed successfully"
}

# Function to install SQLMap
install_sqlmap() {
    print_step "Installing SQLMap..."
    
    SQLMAP_DIR="$HOME/.sqlmap"
    
    if [ ! -d "$SQLMAP_DIR" ]; then
        git clone https://github.com/sqlmapproject/sqlmap.git "$SQLMAP_DIR"
    else
        cd "$SQLMAP_DIR"
        git pull origin master
        cd - > /dev/null
    fi
    
    # Create symlink
    sudo ln -sf "$SQLMAP_DIR/sqlmap.py" /usr/local/bin/sqlmap
    
    print_success "SQLMap installed successfully"
}

# Function to install SSRFMap
install_ssrfmap() {
    print_step "Installing SSRFMap..."
    
    SSRFMAP_DIR="$HOME/.ssrfmap"
    
    if [ ! -d "$SSRFMAP_DIR" ]; then
        git clone https://github.com/swisskyrepo/SSRFmap.git "$SSRFMAP_DIR"
        cd "$SSRFMAP_DIR"
        pip3 install -r requirements.txt
        cd - > /dev/null
    else
        cd "$SSRFMAP_DIR"
        git pull origin master
        pip3 install -r requirements.txt
        cd - > /dev/null
    fi
    
    # Create symlink
    sudo ln -sf "$SSRFMAP_DIR/ssrfmap.py" /usr/local/bin/ssrfmap
    
    print_success "SSRFMap installed successfully"
}

# Function to install XSStrike
install_xsstrike() {
    print_step "Installing XSStrike..."
    
    XSSTRIKE_DIR="$HOME/.xsstrike"
    
    if [ ! -d "$XSSTRIKE_DIR" ]; then
        git clone https://github.com/s0md3v/XSStrike.git "$XSSTRIKE_DIR"
        cd "$XSSTRIKE_DIR"
        pip3 install -r requirements.txt
        cd - > /dev/null
    else
        cd "$XSSTRIKE_DIR"
        git pull origin master
        pip3 install -r requirements.txt
        cd - > /dev/null
    fi
    
    # Create symlink
    sudo ln -sf "$XSSTRIKE_DIR/xsstrike.py" /usr/local/bin/xsstrike
    
    print_success "XSStrike installed successfully"
}

# Function to install Redis
install_redis() {
    print_step "Installing Redis..."
    
    case $OS in
        "macos")
            brew install redis
            brew services start redis
            ;;
        "ubuntu"|"debian")
            sudo apt-get install -y redis-server
            sudo systemctl enable redis-server
            sudo systemctl start redis-server
            ;;
        "centos"|"rhel"|"fedora")
            sudo yum install -y redis
            sudo systemctl enable redis
            sudo systemctl start redis
            ;;
    esac
    
    print_success "Redis installed and started"
}

# Function to create configuration file
create_config() {
    print_step "Creating configuration file..."
    
    cat > config.py << EOF
# API Security Framework Configuration
import os

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this'
    DEBUG = True
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///instance/api_scanner.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security Tools Paths
    ZAP_PATH = os.environ.get('ZAP_PATH') or '$HOME/.zap/zap.sh'
    NUCLEI_PATH = os.environ.get('NUCLEI_PATH') or 'nuclei'
    SQLMAP_PATH = os.environ.get('SQLMAP_PATH') or 'sqlmap'
    SSRFMAP_PATH = os.environ.get('SSRFMAP_PATH') or '$HOME/.ssrfmap/ssrfmap.py'
    XSSTRIKE_PATH = os.environ.get('XSSTRIKE_PATH') or '$HOME/.xsstrike/xsstrike.py'
    
    # Celery Configuration
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or 'redis://localhost:6379/0'
    
    # API Configuration
    API_BASE_URL = os.environ.get('API_BASE_URL') or 'https://api.example.com/'
    TARGET_PORTAL_URL = os.environ.get('TARGET_PORTAL_URL') or 'https://portal.example.com/'
    
    # Admin Credentials
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME') or 'admin'
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD') or 'secure_password_change_this'
    
    # Slack Configuration (optional)
    SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL') or ''
    SLACK_CHANNEL = os.environ.get('SLACK_CHANNEL') or '#security-alerts'
    
    # OpenAI Configuration (optional)
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY') or ''
    
    # Real-time Monitoring Configuration
    REALTIME_CHECK_INTERVAL = 30  # seconds
    REALTIME_CHANGE_THRESHOLD = 0.1  # 10%
    
    # Scan Configuration
    DEFAULT_SCAN_TIMEOUT = 300  # 5 minutes
    MAX_CONCURRENT_SCANS = 5
    
    # Logging Configuration
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'app.log'
EOF
    
    print_success "Configuration file created: config.py"
}

# Function to create environment file
create_env_file() {
    print_step "Creating environment file..."
    
    cat > .env << EOF
# API Security Framework Environment Variables
# Copy this file to .env.local and modify as needed

# Flask Configuration
SECRET_KEY=your-secret-key-change-this
DEBUG=True

# Database Configuration
DATABASE_URL=sqlite:///instance/api_scanner.db

# Security Tools Paths
ZAP_PATH=\$HOME/.zap/zap.sh
NUCLEI_PATH=nuclei
SQLMAP_PATH=sqlmap
SSRFMAP_PATH=\$HOME/.ssrfmap/ssrfmap.py
XSSTRIKE_PATH=\$HOME/.xsstrike/xsstrike.py

# Celery Configuration
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# API Configuration
API_BASE_URL=https://api.example.com/
TARGET_PORTAL_URL=https://portal.example.com/

# Admin Credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=secure_password_change_this

# Slack Configuration (optional)
SLACK_WEBHOOK_URL=
SLACK_CHANNEL=#security-alerts

# OpenAI Configuration (optional)
OPENAI_API_KEY=

# Real-time Monitoring Configuration
REALTIME_CHECK_INTERVAL=30
REALTIME_CHANGE_THRESHOLD=0.1

# Scan Configuration
DEFAULT_SCAN_TIMEOUT=300
MAX_CONCURRENT_SCANS=5

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=app.log
EOF
    
    print_success "Environment file created: .env"
}

# Function to create startup script
create_startup_script() {
    print_step "Creating startup script..."
    
    cat > start.sh << 'EOF'
#!/bin/bash

# APIShield Startup Script

echo "🚀 Starting API Security Framework..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run install_and_run.sh first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if Redis is running
if ! pgrep -x "redis-server" > /dev/null; then
    echo "⚠️  Redis is not running. Starting Redis..."
    case "$(uname -s)" in
        "Darwin")
            brew services start redis
            ;;
        "Linux")
            sudo systemctl start redis
            ;;
        *)
            echo "⚠️  Please start Redis manually"
            ;;
    esac
fi

# Start Celery worker in background
echo "🔧 Starting Celery worker..."
celery -A app.tasks worker --loglevel=info > celery.log 2>&1 &
CELERY_PID=$!

# Wait a moment for Celery to start
sleep 3

# Start the main application
echo "🌐 Starting Flask application..."
python main_app.py > app.log 2>&1 &
APP_PID=$!

echo "✅ API Security Framework started!"
echo "📊 Application PID: $APP_PID"
echo "🔧 Celery PID: $CELERY_PID"
echo "📝 Logs: app.log (app) and celery.log (celery)"
echo "🌐 Dashboard: http://localhost:5001"
echo ""
echo "To stop the application:"
echo "  kill $APP_PID $CELERY_PID"
echo ""
echo "To view logs:"
echo "  tail -f app.log"
echo "  tail -f celery.log"

# Save PIDs to file for easy stopping
echo "$APP_PID $CELERY_PID" > .pids

# Wait for user to stop
trap 'echo "Stopping services..."; kill $APP_PID $CELERY_PID 2>/dev/null; rm -f .pids; exit 0' INT
wait
EOF
    
    chmod +x start.sh
    print_success "Startup script created: start.sh"
}

# Function to create stop script
create_stop_script() {
    print_step "Creating stop script..."
    
    cat > stop.sh << 'EOF'
#!/bin/bash

# APIShield Stop Script

echo "🛑 Stopping API Security Framework..."

# Stop processes using PIDs from file
if [ -f .pids ]; then
    PIDS=$(cat .pids)
    kill $PIDS 2>/dev/null
    rm -f .pids
    echo "✅ Services stopped"
else
    # Fallback: kill by process name
    pkill -f "python main_app.py"
    pkill -f "celery.*worker"
    echo "✅ Services stopped (fallback method)"
fi

# Stop Redis if it was started by brew
if command -v brew &> /dev/null; then
    brew services stop redis 2>/dev/null
fi

echo "✅ All services stopped"
EOF
    
    chmod +x stop.sh
    print_success "Stop script created: stop.sh"
}

# Function to test installations
test_installations() {
    print_step "Testing installations..."
    
    # Test Python
    if command_exists python3; then
        print_success "Python3: $(python3 --version)"
    else
        print_error "Python3 not found"
    fi
    
    # Test Java
    if command_exists java; then
        print_success "Java: $(java -version 2>&1 | head -n 1)"
    else
        print_error "Java not found"
    fi
    
    # Test ZAP
    if [ -f "$HOME/.zap/zap.sh" ]; then
        print_success "ZAP: Found at $HOME/.zap/zap.sh"
    else
        print_warning "ZAP: Not found"
    fi
    
    # Test Nuclei
    if command_exists nuclei; then
        print_success "Nuclei: Found"
    else
        print_warning "Nuclei: Not found"
    fi
    
    # Test SQLMap
    if command_exists sqlmap; then
        print_success "SQLMap: Found"
    else
        print_warning "SQLMap: Not found"
    fi
    
    # Test Redis
    if command_exists redis-server; then
        print_success "Redis: Found"
    else
        print_warning "Redis: Not found"
    fi
}

# Function to start the application
start_application() {
    print_header "Starting APIShield"
    
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        print_error "Virtual environment not found. Please run the installation first."
        exit 1
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Check if Redis is running
    if ! pgrep -x "redis-server" > /dev/null; then
        print_warning "Redis is not running. Starting Redis..."
        case "$(uname -s)" in
            "Darwin")
                brew services start redis
                ;;
            "Linux")
                sudo systemctl start redis
                ;;
            *)
                print_warning "Please start Redis manually"
                ;;
        esac
    fi
    
    # Start Celery worker in background
    print_status "Starting Celery worker..."
    celery -A app.tasks worker --loglevel=info > celery.log 2>&1 &
    CELERY_PID=$!
    
    # Wait a moment for Celery to start
    sleep 3
    
    # Start the main application
    print_status "Starting Flask application..."
    python main_app.py > app.log 2>&1 &
    APP_PID=$!
    
    print_success "API Security Framework started!"
    echo ""
    echo "📊 Application PID: $APP_PID"
    echo "🔧 Celery PID: $CELERY_PID"
    echo "📝 Logs: app.log (app) and celery.log (celery)"
    echo "🌐 Dashboard: http://localhost:5001"
    echo ""
    echo "To stop the application:"
    echo "  kill $APP_PID $CELERY_PID"
    echo "  or use: ./stop.sh"
    echo ""
    echo "To view logs:"
    echo "  tail -f app.log"
    echo "  tail -f celery.log"
    
    # Save PIDs to file for easy stopping
    echo "$APP_PID $CELERY_PID" > .pids
    
    # Wait for user to stop
    trap 'echo ""; print_status "Stopping services..."; kill $APP_PID $CELERY_PID 2>/dev/null; rm -f .pids; print_success "Services stopped"; exit 0' INT
    
    echo ""
    print_status "Press Ctrl+C to stop the application"
    wait
}

# Function to display next steps
show_next_steps() {
    echo ""
    print_header "APIShield Setup Completed Successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Review and modify config.py if needed"
    echo "2. Start the application: ./start.sh"
    echo "3. Access the dashboard: http://localhost:5001"
    echo "4. Stop the application: ./stop.sh"
    echo ""
    echo "Default credentials:"
    echo "  Username: admin"
    echo "  Password: secure_password_change_this"
    echo ""
    echo "Important: Change the default password in config.py!"
    echo ""
    echo "For more information, check the README.md file."
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  install     Install all dependencies and setup environment"
    echo "  run         Start the application (requires installation first)"
    echo "  full        Install and run in one go (default)"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 install    # Install only"
    echo "  $0 run        # Run only (after installation)"
    echo "  $0 full       # Install and run"
    echo "  $0            # Same as 'full'"
}

# Main installation function
install_framework() {
    print_header "Installing APIShield"
    
    # Detect OS
    detect_os
    
    # Install system dependencies
    install_system_deps
    
    # Install Python dependencies
    install_python_deps
    
    # Install security tools
    install_zap
    install_nuclei
    install_sqlmap
    install_ssrfmap
    install_xsstrike
    
    # Install Redis
    install_redis
    
    # Create configuration files
    create_config
    create_env_file
    
    # Create startup/stop scripts
    create_startup_script
    create_stop_script
    
    # Test installations
    test_installations
    
    # Show next steps
    show_next_steps
}

# Main function
main() {
    case "${1:-full}" in
        "install")
            install_framework
            ;;
        "run")
            start_application
            ;;
        "full")
            install_framework
            echo ""
            print_status "Installation complete! Starting application..."
            echo ""
            start_application
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
