@echo off
echo =========================================
echo  LLM Security Gateway - Full Evaluation
echo  Generates all 5 mandatory tables
echo =========================================
echo.
cd /d "%~dp0"
python evaluate.py
echo.
pause
