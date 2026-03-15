@echo off
echo ========================================== 
echo  LLM Security Gateway - Flask API Server
echo ========================================== 
echo.
echo Server will start on http://localhost:5000
echo Press Ctrl+C to stop.
echo.
cd /d "%~dp0"
python app.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Failed to start server.
    echo Make sure you ran setup\setup.bat first.
    pause
)
