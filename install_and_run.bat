@echo off
REM APIShield - Complete Install and Run Script for Windows
REM This script will install all dependencies, set up the environment, and run the application

setlocal enabledelayedexpansion

echo 🚀 API Security Framework - Windows Install and Run Script
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

REM Check command line arguments
set "ACTION=%1"
if "%ACTION%"=="" set "ACTION=full"

if "%ACTION%"=="help" goto :show_help
if "%ACTION%"=="-h" goto :show_help
if "%ACTION%"=="--help" goto :show_help
if "%ACTION%"=="install" goto :install_framework
if "%ACTION%"=="run" goto :start_application
if "%ACTION%"=="full" goto :install_and_run
goto :show_help

:show_help
echo Usage: %0 [OPTION]
echo.
echo Options:
echo   install     Install all dependencies and setup environment
echo   run         Start the application (requires installation first)
echo   full        Install and run in one go (default)
echo   help        Show this help message
echo.
echo Examples:
echo   %0 install    # Install only
echo   %0 run        # Run only (after installation)
echo   %0 full       # Install and run
echo   %0            # Same as 'full'
echo.
pause
exit /b 0

:install_framework
echo.
echo =================================
echo Installing API Security Framework
echo =================================
echo.

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

REM Start Redis service
echo [INFO] Starting Redis service...
net start Redis
if %errorLevel% neq 0 (
    echo [WARNING] Failed to start Redis service
)

REM Create configuration file
echo [INFO] Creating configuration file...
(
    echo # API Security Framework Configuration
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
    echo # API Security Framework Environment Variables
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
    echo REM API Security Framework Startup Script
    echo.
    echo echo 🚀 Starting API Security Framework...
    echo.
    echo REM Check if virtual environment exists
    echo if not exist "venv" ^(
    echo     echo ❌ Virtual environment not found. Please run install_and_run.bat first.
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
    echo REM API Security Framework Stop Script
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

if "%ACTION%"=="install" (
    echo Installation complete! Run 'start.bat' to start the application.
    pause
    exit /b 0
)

goto :start_application

:start_application
echo.
echo =================================
echo Starting API Security Framework
echo =================================
echo.

REM Check if virtual environment exists
if not exist "venv" (
    echo [ERROR] Virtual environment not found. Please run the installation first.
    pause
    exit /b 1
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Check if Redis is running
sc query Redis | find "RUNNING" >nul
if %errorLevel% neq 0 (
    echo [WARNING] Redis is not running. Starting Redis...
    net start Redis
)

REM Start Celery worker in background
echo [INFO] Starting Celery worker...
start /B celery -A app.tasks worker --loglevel=info > celery.log 2>&1

REM Wait a moment for Celery to start
timeout /t 3 /nobreak >nul

REM Start the main application
echo [INFO] Starting Flask application...
start /B python main_app.py > app.log 2>&1

echo [SUCCESS] API Security Framework started!
echo.
echo 🌐 Dashboard: http://localhost:5001
echo.
echo To stop the application, run stop.bat
echo.
echo To view logs:
echo   type app.log
echo   type celery.log
echo.
echo Press any key to stop the application...
pause >nul

REM Stop the application
echo [INFO] Stopping services...
taskkill /f /im python.exe 2>nul
taskkill /f /im celery.exe 2>nul
echo [SUCCESS] Services stopped
pause
exit /b 0

:install_and_run
call :install_framework
echo.
echo [INFO] Installation complete! Starting application...
echo.
call :start_application
exit /b 0
