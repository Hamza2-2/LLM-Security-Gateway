@echo off
echo Starting LLM Security Gateway GUI...
cd /d "%~dp0"
python app.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Failed to start GUI.
    echo Make sure you ran setup\setup.bat first.
    pause
)
