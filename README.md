# 🚀 APIShield - API Security Framework

APIShield is a comprehensive, real-time API security monitoring and vulnerability scanning framework that automatically detects API changes and triggers security scans.

## ✨ Features

### 🔍 **Real-Time API Monitoring**
- **Automatic Change Detection**: Monitors API endpoints for changes in real-time
- **Baseline Management**: Establishes baseline snapshots and tracks deviations
- **Smart Scanning**: Only scans changed endpoints, not entire services
- **Change History**: Maintains detailed logs of all API modifications

### 🛡️ **Multi-Tool Security Scanning**
- **OWASP ZAP**: Web application security testing
- **Nuclei**: Fast vulnerability scanning with extensive templates
- **SQLMap**: SQL injection detection and exploitation
- **SSRFMap**: Server-Side Request Forgery testing
- **XSStrike**: Advanced XSS detection and exploitation

### 🎯 **Intelligent Scanning**
- **Parameter Generation**: AI-powered parameter value generation for comprehensive testing
- **Duplicate Prevention**: Prevents duplicate vulnerability reports
- **Risk Scoring**: Automated risk assessment and prioritization
- **Evidence Collection**: Detailed request/response capture for vulnerability validation

### 📊 **Comprehensive Dashboard**
- **Real-Time Status**: Live monitoring of API changes and scan progress
- **Vulnerability Management**: Centralized vulnerability tracking and reporting
- **Service Discovery**: Automatic API service detection and cataloging
- **Scan History**: Complete audit trail of all security assessments

### 🔧 **Enterprise Features**
- **Slack Integration**: Real-time security alerts and notifications
- **Celery Task Queue**: Scalable background processing
- **Redis Backend**: High-performance caching and message queuing
- **Multi-User Support**: Role-based access control and user management

## 🚀 Quick Start

### Prerequisites
- **Python 3.8+**
- **Java 11+** (required for OWASP ZAP)
- **Git**
- **Redis** (for task queuing)

### Installation

#### 🐧 **Linux/macOS**
```bash
# Clone the repository
git clone https://github.com/yourusername/apishield.git
cd apishield

# Run the setup script
chmod +x setup.sh
./setup.sh
```

#### 🪟 **Windows**
```cmd
# Clone the repository
git clone https://github.com/yourusername/apishield.git
cd apishield

# Run the setup script as Administrator
setup.bat
```

### 🚀 **Starting the Application**

#### Linux/macOS
```bash
./start.sh
```

#### Windows
```cmd
start.bat
```

### 🛑 **Stopping the Application**

#### Linux/macOS
```bash
./stop.sh
```

#### Windows
```cmd
stop.bat
```

## 📋 **Setup Script Features**

The setup scripts automatically:

1. **Detect Operating System** and use appropriate package managers
2. **Install System Dependencies** (Python, Java, Git, Redis)
3. **Install Security Tools**:
   - OWASP ZAP (latest version)
   - Nuclei (latest version)
   - SQLMap (from GitHub)
   - SSRFMap (from GitHub)
   - XSStrike (from GitHub)
4. **Create Python Virtual Environment** and install dependencies
5. **Generate Configuration Files** with proper tool paths
6. **Create Startup/Stop Scripts** for easy management
7. **Test All Installations** to ensure everything works

## ⚙️ **Configuration**

### Environment Variables
The framework supports configuration via environment variables:

```bash
# Security Tools Paths
export ZAP_PATH="$HOME/.zap/zap.sh"
export NUCLEI_PATH="nuclei"
export SQLMAP_PATH="sqlmap"
export SSRFMAP_PATH="$HOME/.ssrfmap/ssrfmap.py"
export XSSTRIKE_PATH="$HOME/.xsstrike/xsstrike.py"

# API Configuration
export API_BASE_URL="https://your-api.com/"
export TARGET_PORTAL_URL="https://your-portal.com/"

# Admin Credentials
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="your-secure-password"

# Optional Integrations
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export OPENAI_API_KEY="sk-..."
```

### Configuration File
The setup script creates a `config.py` file with all necessary settings. Modify this file to customize:

- Security tool paths
- API endpoints
- Database configuration
- Scan parameters
- Notification settings

## 🔧 **Usage**

### 1. **Initial Setup**
```bash
# Run setup script
./setup.sh

# Review and modify configuration
nano config.py
```

### 2. **Start Services**
```bash
# Start the framework
./start.sh

# Access dashboard
open http://localhost:5001
```

### 3. **Configure Monitoring**
1. Navigate to **Real-Time Monitoring** in the dashboard
2. Click **"Establish Baseline"** to create initial API snapshot
3. Enable **Auto-Scanning** for automatic vulnerability detection
4. Configure **Security Tools** to use for scanning

### 4. **Monitor API Changes**
- The system automatically detects API modifications
- Changed endpoints are automatically scanned for vulnerabilities
- Real-time notifications are sent via Slack (if configured)
- All changes and scan results are logged in the dashboard

## 📊 **Dashboard Features**

### **Main Dashboard**
- System status overview
- Vulnerability statistics
- Recent scan results
- Service count and health

### **Real-Time Monitoring**
- Live API change detection
- Baseline management
- Auto-scan configuration
- Change history and logs

### **Services Management**
- API service discovery
- Endpoint cataloging
- Service health monitoring
- Manual scan triggering

### **Vulnerability Management**
- Vulnerability database
- Risk scoring and prioritization
- Evidence collection
- False positive management

### **Scan Management**
- Manual scan configuration
- Scan history and results
- Tool-specific configurations
- Performance metrics

## 🛠️ **Security Tools Integration**

### **OWASP ZAP**
- **Spider Crawling**: Automatic endpoint discovery
- **Active Scanning**: Vulnerability detection
- **Context Management**: Targeted scanning
- **API Key Support**: Secure API access

### **Nuclei**
- **Template-Based Scanning**: Extensive vulnerability templates
- **Fast Execution**: High-performance scanning
- **Custom Templates**: User-defined security checks
- **Output Formatting**: Structured results

### **SQLMap**
- **SQL Injection Detection**: Comprehensive SQLi testing
- **Parameter Testing**: All endpoint parameters
- **Database Fingerprinting**: Target database identification
- **Exploitation**: Proof-of-concept attacks

### **SSRFMap**
- **Server-Side Request Forgery**: SSRF vulnerability testing
- **Internal Network Discovery**: Internal service enumeration
- **Cloud Service Testing**: AWS, Azure, GCP SSRF checks
- **Custom Payloads**: User-defined SSRF vectors

### **XSStrike**
- **Advanced XSS Detection**: Sophisticated XSS identification
- **Payload Generation**: Custom XSS vectors
- **Filter Bypass**: WAF evasion techniques
- **Context-Aware Testing**: DOM, reflected, stored XSS

## 🔒 **Security Features**

### **Authentication & Authorization**
- **Multi-User Support**: Role-based access control
- **Secure Password Storage**: bcrypt hashing
- **Session Management**: Secure session handling
- **API Key Protection**: Secure tool integration

### **Data Protection**
- **Input Validation**: Comprehensive input sanitization
- **SQL Injection Prevention**: Parameterized queries
- **XSS Protection**: Output encoding
- **CSRF Protection**: Cross-site request forgery prevention

### **Audit & Compliance**
- **Complete Audit Trail**: All actions logged
- **Change Tracking**: API modification history
- **Scan Records**: Comprehensive scan documentation
- **Vulnerability History**: Temporal vulnerability tracking

## 📈 **Performance & Scalability**

### **Task Queue System**
- **Celery Integration**: Asynchronous task processing
- **Redis Backend**: High-performance message queuing
- **Worker Scaling**: Multiple worker processes
- **Task Prioritization**: Critical scan prioritization

### **Database Optimization**
- **SQLAlchemy ORM**: Efficient database operations
- **Connection Pooling**: Optimized database connections
- **Query Optimization**: Efficient data retrieval
- **Indexing**: Fast search and filtering

### **Caching Strategy**
- **Redis Caching**: Fast data access
- **Template Caching**: Optimized rendering
- **API Response Caching**: Reduced external calls
- **Scan Result Caching**: Improved performance

## 🚨 **Troubleshooting**

### **Common Issues**

#### **ZAP Not Starting**
```bash
# Check Java installation
java -version

# Verify ZAP path
ls -la ~/.zap/zap.sh

# Check permissions
chmod +x ~/.zap/zap.sh
```

#### **Redis Connection Issues**
```bash
# Check Redis status
redis-cli ping

# Start Redis service
sudo systemctl start redis  # Linux
brew services start redis   # macOS
net start Redis            # Windows
```

#### **Permission Errors**
```bash
# Fix file permissions
chmod +x *.sh
chmod +x *.py

# Check virtual environment
source venv/bin/activate
```

### **Log Files**
- **Application Logs**: `app.log`
- **Celery Logs**: `celery.log`
- **ZAP Logs**: `zap.log` (if enabled)

### **Debug Mode**
Enable debug mode in `config.py`:
```python
DEBUG = True
LOG_LEVEL = 'DEBUG'
```

## 🤝 **Contributing**

### **Development Setup**
```bash
# Clone repository
git clone https://github.com/yourusername/api-security-framework.git
cd api-security-framework

# Create development branch
git checkout -b feature/your-feature

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Format code
black .
flake8 .
```

### **Code Standards**
- **Python**: PEP 8 compliance
- **Testing**: Minimum 80% coverage
- **Documentation**: Docstrings for all functions
- **Type Hints**: Python type annotations

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- **OWASP ZAP**: Web application security testing
- **Nuclei**: Fast vulnerability scanning
- **SQLMap**: SQL injection testing
- **SSRFMap**: SSRF vulnerability testing
- **XSStrike**: Advanced XSS detection

## 📞 **Support**

- **Issues**: [GitHub Issues](https://github.com/yourusername/api-security-framework/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/api-security-framework/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/api-security-framework/wiki)

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Always ensure you have proper authorization before testing any systems or applications.
