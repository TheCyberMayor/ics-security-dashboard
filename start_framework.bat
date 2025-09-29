@echo off
REM ICS Cybersecurity Framework Startup Script
REM Runs the complete framework with dashboard integration

echo ================================
echo  ICS Cybersecurity Framework
echo ================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo.
    echo Please install Python 3.8+ from:
    echo https://www.python.org/downloads/
    echo.
    echo Or use Windows Store:
    echo winget install Python.Python.3.11
    echo.
    pause
    exit /b 1
)

REM Navigate to backend directory
cd /d "%~dp0backend" 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Backend directory not found
    echo Expected: %~dp0backend
    pause
    exit /b 1
)

echo [INFO] Checking Python dependencies...

REM Check if requirements are installed
python -c "import fastapi, uvicorn, pandas, numpy, networkx, sklearn" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Installing Python dependencies...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install dependencies
        echo.
        echo Try manually:
        echo   cd backend
        echo   pip install -r requirements.txt
        pause
        exit /b 1
    )
    echo [OK] Dependencies installed successfully
) else (
    echo [OK] Dependencies already installed
)

echo.
echo [INFO] Starting ICS Cybersecurity Framework...
echo.
echo Choose startup mode:
echo   1. Full Framework + Dashboard (Recommended)
echo   2. Framework Only (Assessment + Validation)
echo   3. Dashboard Only (Demo Mode)
echo   4. Quick Demo (Fast training, minimal validation)
echo.

set /p choice="Enter choice (1-4): "

if "%choice%"=="1" (
    echo [INFO] Starting full framework with dashboard...
    python main.py --mode full --api
) else if "%choice%"=="2" (
    echo [INFO] Starting framework assessment and validation...
    python main.py --mode full
) else if "%choice%"=="3" (
    echo [INFO] Starting dashboard in demo mode...
    echo [INFO] Opening dashboard at http://localhost:8080
    cd ..\dashboard
    python -m http.server 8080
) else if "%choice%"=="4" (
    echo [INFO] Starting quick demo...
    echo [INFO] This uses reduced training parameters for faster startup
    python -c "
import json
config = {
    'phases': {'threat_collection': True, 'graph_analysis': True, 'risk_classification': True, 'dynamic_mitigation': True, 'validation': True},
    'training': {'threat_samples': 1000, 'mitigation_episodes': 100, 'validation_samples': 200},
    'output': {'export_data': True, 'generate_reports': True, 'save_models': True}
}
with open('config.json', 'w') as f: json.dump(config, f, indent=2)
print('Quick demo config created')
"
    python main.py --mode full --api
) else (
    echo [ERROR] Invalid choice
    pause
    exit /b 1
)

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Framework execution failed
    echo.
    echo Troubleshooting:
    echo   1. Check that all dependencies are installed
    echo   2. Ensure no other process is using port 8000
    echo   3. Check the log file: ics_framework.log
    echo.
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Framework execution completed
echo.
echo Output files are in the 'output' directory
echo Check ics_framework.log for detailed execution logs
echo.
pause