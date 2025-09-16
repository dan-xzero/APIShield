@echo off
REM APIShield - Windows Setup Script
REM This script will install all necessary tools and dependencies for the API Security Framework

setlocal enabledelayedexpansion

echo 🚀 APIShield Setup Script
echo ================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Running as administrator
) else (
    echo [ERROR] This script must be run as administrator
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Check if Chocolatey is installed
where choco >nul 2>&1
if %errorLevel% neq 0 (
    echo [INFO] Installing Chocolatey package manager...
    powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    if %errorLevel% neq 0 (
        echo [ERROR] Failed to install Chocolatey
        pause
        exit /b 1
    )
    echo [SUCCESS] Chocolatey installed successfully
) else (
    echo [INFO] Chocolatey already installed
)

REM Install system dependencies
echo [INFO] Installing system dependencies...
choco install python git jdk11 redis -y
if %errorLevel% neq 0 (
    echo [ERROR] Failed to install system dependencies
    pause
    exit /b 1
)

REM Refresh environment variables
call refreshenv

REM Create virtual environment
echo [INFO] Creating Python virtual environment...
if not exist "venv" (
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Upgrade pip
python -m pip install --upgrade pip

REM Create requirements.txt if it doesn't exist
if not exist "requirements.txt" (
    echo [INFO] Creating requirements.txt...
    (
        echo # API Security Framework Dependencies
        echo.
        echo # Flask and extensions
        echo Flask==2.3.3
        echo Flask-SQLAlchemy==3.0.5
        echo Flask-Login==0.6.3
        echo Flask-WTF==1.1.1
        echo WTForms==3.0.1
        echo.
        echo # Database
        echo SQLAlchemy==2.0.21
        echo.
        echo # Task queue
        echo celery==5.3.1
        echo redis==4.6.0
        echo.
        echo # HTTP requests
        echo requests==2.31.0
        echo urllib3==2.0.4
        echo.
        echo # Security and cryptography
        echo bcrypt==4.0.1
        echo cryptography==41.0.4
        echo.
        echo # Data processing
        echo pandas==2.0.3
        echo numpy==1.24.3
        echo.
        echo # AI and machine learning
        echo openai==0.28.1
        echo.
        echo # Utilities
        echo python-dotenv==1.0.0
        echo click==8.1.7
        echo rich==13.5.2
        echo tqdm==4.66.1
        echo.
        echo # Development and testing
        echo pytest==7.4.2
        echo pytest-cov==4.1.0
        echo black==23.7.0
        echo flake8==6.0.0
    ) > requirements.txt
    echo [SUCCESS] requirements.txt created
)

REM Install Python dependencies
echo [INFO] Installing Python dependencies...
pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo [ERROR] Failed to install Python dependencies
    pause
    exit /b 1
)

REM Install OWASP ZAP
echo [INFO] Installing OWASP ZAP...
choco install owasp-zap -y
if %errorLevel% neq 0 (
    echo [WARNING] Failed to install ZAP via Chocolatey, downloading manually...
    
    REM Download ZAP manually
    set ZAP_VERSION=2.14.0
    set ZAP_URL=https://github.com/zaproxy/zaproxy/releases/download/v%ZAP_VERSION%/ZAP_%ZAP_VERSION%_Windows.zip
    set ZAP_ZIP=%TEMP%\ZAP_%ZAP_VERSION%_Windows.zip
    set ZAP_DIR=%USERPROFILE%\.zap
    
    if not exist "%ZAP_DIR%" mkdir "%ZAP_DIR%"
    
    echo Downloading ZAP...
    powershell -Command "Invoke-WebRequest -Uri '%ZAP_URL%' -OutFile '%ZAP_ZIP%'"
    
    if exist "%ZAP_ZIP%" (
        echo Extracting ZAP...
        powershell -Command "Expand-Archive -Path '%ZAP_ZIP%' -DestinationPath '%ZAP_DIR%' -Force"
        del "%ZAP_ZIP%"
        echo [SUCCESS] ZAP installed manually
    ) else (
        echo [ERROR] Failed to download ZAP
    )
) else (
    echo [SUCCESS] ZAP installed via Chocolatey
)

REM Install Nuclei
echo [INFO] Installing Nuclei...
choco install nuclei -y
if %errorLevel% neq 0 (
    echo [WARNING] Failed to install Nuclei via Chocolatey
)

REM Install SQLMap
echo [INFO] Installing SQLMap...
if not exist "%USERPROFILE%\.sqlmap" (
    git clone https://github.com/sqlmapproject/sqlmap.git "%USERPROFILE%\.sqlmap"
    echo [SUCCESS] SQLMap installed
) else (
    echo [INFO] SQLMap already installed
)

REM Install SSRFMap
echo [INFO] Installing SSRFMap...
if not exist "%USERPROFILE%\.ssrfmap" (
    git clone https://github.com/swisskyrepo/SSRFmap.git "%USERPROFILE%\.ssrfmap"
    cd "%USERPROFILE%\.ssrfmap"
    pip install -r requirements.txt
    cd /d "%~dp0"
    echo [SUCCESS] SSRFMap installed
) else (
    echo [INFO] SSRFMap already installed
)

REM Install XSStrike
echo [INFO] Installing XSStrike...
if not exist "%USERPROFILE%\.xsstrike" (
    git clone https://github.com/s0md3v/XSStrike.git "%USERPROFILE%\.xsstrike"
    cd "%USERPROFILE%\.xsstrike"
    pip install -r requirements.txt
    cd /d "%~dp0"
    echo [SUCCESS] XSStrike installed
) else (
    echo [INFO] XSStrike already installed
)

REM Install VulnAPI
echo [INFO] Installing VulnAPI...
echo [WARNING] Please install VulnAPI manually from:
echo [WARNING] https://github.com/cerberauth/vulnapi/releases
echo [WARNING] Download the latest Windows release, extract it, and add the location of vulnapi.exe to your system's PATH.
echo.

REM Install WuppieFuzz
echo [INFO] Installing WuppieFuzz...
echo [WARNING] Please install WuppieFuzz manually from:
echo [WARNING] https://github.com/TNO-S3/WuppieFuzz/releases
echo [WARNING] Download the latest Windows release, extract it, and add the location of wuppiefuzz.exe to your system's PATH.
echo.

REM Install GraphQL Cop
echo [INFO] Installing GraphQL Cop...
if not exist "%USERPROFILE%\.graphql-cop" (
    git clone https://github.com/dolevf/graphql-cop.git "%USERPROFILE%\.graphql-cop"
    cd "%USERPROFILE%\.graphql-cop"
    pip install -r requirements.txt
    cd /d "%~dp0"
    echo [SUCCESS] GraphQL Cop installed
) else (
    echo [INFO] GraphQL Cop already installed
)

REM Start Redis service
echo [INFO] Starting Redis service...
net start Redis
if %errorLevel% neq 0 (
    echo [WARNING] Failed to start Redis service
)

REM Create configuration file
echo [INFO] Creating configuration file...
(
    echo # APIShield Configuration
    echo import os
    echo.
    echo class Config:
    echo     # Flask Configuration
    echo     SECRET_KEY = os.environ.get^('SECRET_KEY'^) or 'your-secret-key-change-this'
    echo     DEBUG = True
    echo.
    echo     # Database Configuration
    echo     SQLALCHEMY_DATABASE_URI = os.environ.get^('DATABASE_URL'^) or 'sqlite:///instance/api_scanner.db'
    echo     SQLALCHEMY_TRACK_MODIFICATIONS = False
    echo.
    echo     # Security Tools Paths
    echo     ZAP_PATH = os.environ.get^('ZAP_PATH'^) or r'%USERPROFILE%\.zap\ZAP_2.14.0\zap.bat'
    echo     NUCLEI_PATH = os.environ.get^('NUCLEI_PATH'^) or 'nuclei'
    echo     SQLMAP_PATH = os.environ.get^('SQLMAP_PATH'^) or r'%USERPROFILE%\.sqlmap\sqlmap.py'
    echo     SSRFMAP_PATH = os.environ.get^('SSRFMAP_PATH'^) or r'%USERPROFILE%\.ssrfmap\ssrfmap.py'
    echo     XSSTRIKE_PATH = os.environ.get^('XSSTRIKE_PATH'^) or r'%USERPROFILE%\.xsstrike\xsstrike.py'
    echo     VULNAPI_PATH = os.environ.get^('VULNAPI_PATH'^) or 'vulnapi'
    echo     WUPPIEFUZZ_PATH = os.environ.get^('WUPPIEFUZZ_PATH'^) or 'wuppiefuzz'
    echo     GRAPHQL_COP_PATH = os.environ.get^('GRAPHQL_COP_PATH'^) or r'%USERPROFILE%\.graphql-cop\graphql-cop.py'
    echo.
    echo     # Celery Configuration
    echo     CELERY_BROKER_URL = os.environ.get^('CELERY_BROKER_URL'^) or 'redis://localhost:6379/0'
    echo     CELERY_RESULT_BACKEND = os.environ.get^('CELERY_RESULT_BACKEND'^) or 'redis://localhost:6379/0'
    echo.
    echo     # API Configuration
    echo     API_BASE_URL = os.environ.get^('API_BASE_URL'^) or 'https://api.example.com/'
    echo     TARGET_PORTAL_URL = os.environ.get^('TARGET_PORTAL_URL'^) or 'https://portal.example.com/'
    echo.
    echo     # Admin Credentials
    echo     ADMIN_USERNAME = os.environ.get^('ADMIN_USERNAME'^) or 'admin'
    echo     ADMIN_PASSWORD = os.environ.get^('ADMIN_PASSWORD'^) or 'secure_password_change_this'
    echo.
    echo     # Slack Configuration ^(optional^)
    echo     SLACK_WEBHOOK_URL = os.environ.get^('SLACK_WEBHOOK_URL'^) or ''
    echo     SLACK_CHANNEL = os.environ.get^('SLACK_CHANNEL'^) or '#security-alerts'
    echo.
    echo     # OpenAI Configuration ^(optional^)
    echo     OPENAI_API_KEY = os.environ.get^('OPENAI_API_KEY'^) or ''
    echo.
    echo     # Real-time Monitoring Configuration
    echo     REALTIME_CHECK_INTERVAL = 30  # seconds
    echo     REALTIME_CHANGE_THRESHOLD = 0.1  # 10%%
    echo.
    echo     # Scan Configuration
    echo     DEFAULT_SCAN_TIMEOUT = 300  # 5 minutes
    echo     MAX_CONCURRENT_SCANS = 5
    echo.
    echo     # Logging Configuration
    echo     LOG_LEVEL = 'INFO'
    echo     LOG_FILE = 'app.log'
) > config.py
echo [SUCCESS] Configuration file created: config.py

REM Create environment file
echo [INFO] Creating environment file...
(
    echo # APIShield Environment Variables
    echo # Copy this file to .env.local and modify as needed
    echo.
    echo # Flask Configuration
    echo SECRET_KEY=your-secret-key-change-this
    echo DEBUG=True
    echo.
    echo # Database Configuration
    echo DATABASE_URL=sqlite:///instance/api_scanner.db
    echo.
    echo # Security Tools Paths
    echo ZAP_PATH=%%USERPROFILE%%\.zap\ZAP_2.14.0\zap.bat
    echo NUCLEI_PATH=nuclei
    echo SQLMAP_PATH=%%USERPROFILE%%\.sqlmap\sqlmap.py
    echo SSRFMAP_PATH=%%USERPROFILE%%\.ssrfmap\ssrfmap.py
    echo XSSTRIKE_PATH=%%USERPROFILE%%\.xsstrike\xsstrike.py
    echo VULNAPI_PATH=vulnapi
    echo WUPPIEFUZZ_PATH=wuppiefuzz
    echo GRAPHQL_COP_PATH=%%USERPROFILE%%\.graphql-cop\graphql-cop.py
    echo.
    echo # Celery Configuration
    echo CELERY_BROKER_URL=redis://localhost:6379/0
    echo CELERY_RESULT_BACKEND=redis://localhost:6379/0
    echo.
    echo # API Configuration
echo API_BASE_URL=https://api.example.com/
echo TARGET_PORTAL_URL=https://portal.example.com/
    echo.
    echo # Admin Credentials
    echo ADMIN_USERNAME=admin
    echo ADMIN_PASSWORD=secure_password_change_this
    echo.
    echo # Slack Configuration ^(optional^)
    echo SLACK_WEBHOOK_URL=
    echo SLACK_CHANNEL=#security-alerts
    echo.
    echo # OpenAI Configuration ^(optional^)
    echo OPENAI_API_KEY=
    echo.
    echo # Real-time Monitoring Configuration
    echo REALTIME_CHECK_INTERVAL=30
    echo REALTIME_CHANGE_THRESHOLD=0.1
    echo.
    echo # Scan Configuration
    echo DEFAULT_SCAN_TIMEOUT=300
    echo MAX_CONCURRENT_SCANS=5
    echo.
    echo # Logging Configuration
    echo LOG_LEVEL=INFO
    echo LOG_FILE=app.log
) > .env
echo [SUCCESS] Environment file created: .env

REM Create startup script
echo [INFO] Creating startup script...
(
    echo @echo off
    echo REM APIShield Startup Script
    echo.
    echo echo 🚀 Starting API Security Framework...
    echo.
    echo REM Check if virtual environment exists
    echo if not exist "venv" ^(
    echo     echo ❌ Virtual environment not found. Please run setup.bat first.
    echo     pause
    echo     exit /b 1
    echo ^)
    echo.
    echo REM Activate virtual environment
    echo call venv\Scripts\activate.bat
    echo.
    echo REM Check if Redis is running
    echo sc query Redis ^| find "RUNNING" ^>nul
    echo if %%errorLevel%% neq 0 ^(
    echo     echo ⚠️  Redis is not running. Starting Redis...
    echo     net start Redis
    echo ^)
    echo.
    echo REM Start Celery worker in background
    echo echo 🔧 Starting Celery worker...
    echo start /B celery -A app.tasks worker --loglevel=info ^> celery.log 2^>^&1
    echo.
    echo REM Wait a moment for Celery to start
    echo timeout /t 3 /nobreak ^>nul
    echo.
    echo REM Start the main application
    echo echo 🌐 Starting Flask application...
    echo start /B python main_app.py ^> app.log 2^>^&1
    echo.
    echo echo ✅ API Security Framework started!
    echo echo 🌐 Dashboard: http://localhost:5001
    echo echo.
    echo echo To stop the application, close this window and run stop.bat
    echo echo.
    echo echo To view logs:
    echo echo   type app.log
    echo echo   type celery.log
    echo.
    echo pause
) > start.bat
echo [SUCCESS] Startup script created: start.bat

REM Create stop script
echo [INFO] Creating stop script...
(
    echo @echo off
    echo REM APIShield Stop Script
    echo.
    echo echo 🛑 Stopping API Security Framework...
    echo.
    echo REM Stop processes by name
    echo taskkill /f /im python.exe 2^>nul
    echo taskkill /f /im celery.exe 2^>nul
    echo.
    echo echo ✅ All services stopped
    echo pause
) > stop.bat
echo [SUCCESS] Stop script created: stop.bat

REM Test installations
echo [INFO] Testing installations...

REM Test Python
python --version >nul 2>&1
if %errorLevel% == 0 (
    echo [SUCCESS] Python: 
    python --version
) else (
    echo [ERROR] Python not found
)

REM Test Java
java -version >nul 2>&1
if %errorLevel% == 0 (
    echo [SUCCESS] Java: 
    java -version 2>&1 | findstr "version"
) else (
    echo [ERROR] Java not found
)

REM Test ZAP
if exist "%USERPROFILE%\.zap\ZAP_2.14.0\zap.bat" (
    echo [SUCCESS] ZAP: Found at %USERPROFILE%\.zap\ZAP_2.14.0\zap.bat
) else (
    echo [WARNING] ZAP: Not found
)

REM Test Nuclei
nuclei --version >nul 2>&1
if %errorLevel% == 0 (
    echo [SUCCESS] Nuclei: Found
) else (
    echo [WARNING] Nuclei: Not found
)

REM Test SQLMap
if exist "%USERPROFILE%\.sqlmap\sqlmap.py" (
    echo [SUCCESS] SQLMap: Found
) else (
    echo [WARNING] SQLMap: Not found
)

REM Test Redis
redis-cli ping >nul 2>&1
if %errorLevel% == 0 (
    echo [SUCCESS] Redis: Found
) else (
    echo [WARNING] Redis: Not found
)

REM Show next steps
echo.
echo 🎉 Setup completed successfully!
echo.
echo Next steps:
echo 1. Review and modify config.py if needed
echo 2. Start the application: start.bat
echo 3. Access the dashboard: http://localhost:5001
echo 4. Stop the application: stop.bat
echo.
echo Default credentials:
echo   Username: admin
echo   Password: secure_password_change_this
echo.
echo Important: Change the default password in config.py!
echo.
echo For more information, check the README.md file.
echo.
pause
