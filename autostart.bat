@echo off
title IoT Security Tester
echo Starting IoT Security Tester...
echo.

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Install Python 3.8+ and add it to PATH.
    pause
    exit /b 1
)

if not exist "requirements.txt" (
    echo ERROR: Run this from the project root directory.
    pause
    exit /b 1
)

if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo Virtual environment created.
    echo.
)

call venv\Scripts\activate

if not exist ".deps_installed" (
    echo Installing dependencies...
    pip install -r requirements.txt --quiet
    if %errorlevel% neq 0 (
        echo ERROR: pip install failed. Check requirements.txt and your internet connection.
        pause
        exit /b 1
    )
    echo. > .deps_installed
    echo Dependencies installed.
    echo.
)

echo Open http://localhost:8080 in your browser.
echo Press Ctrl+C to stop.
echo.
python app.py
pause