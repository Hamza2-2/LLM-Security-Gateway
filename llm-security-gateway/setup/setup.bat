@echo off
echo =============================== 
echo  LLM Security Gateway - Setup
echo =============================== 
echo.
cd /d "%~dp0"

echo [1/3] Installing Python dependencies...
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: pip install failed.
    pause
    exit /b 1
)

echo.
echo [2/3] Downloading spaCy language model...
python -m spacy download en_core_web_lg
if %ERRORLEVEL% NEQ 0 (
    echo WARNING: en_core_web_lg failed. Trying smaller model...
    python -m spacy download en_core_web_sm
)

echo.
echo [3/3] Verifying installation...
python -c "from presidio_analyzer import AnalyzerEngine; print('  Presidio OK')"
python -c "import flask; print('  Flask OK')"
python -c "import spacy; nlp = spacy.load('en_core_web_lg'); print('  spaCy OK')" 2>nul || python -c "import spacy; nlp = spacy.load('en_core_web_sm'); print('  spaCy OK (small model)')"

echo.
echo ==============================================
echo  Setup complete! You can now run:
echo    gui\run_gui.bat          - Tkinter GUI
echo    server\run_server.bat    - Flask API
echo    evaluation\run_test.bat  - Quick tests
echo    evaluation\run_eval.bat  - Full evaluation
echo ==============================================
pause
