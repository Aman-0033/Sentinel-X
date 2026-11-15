@echo off
setlocal enabledelayedexpansion
title Sentinel-X SOC Live Demonstration Launcher

echo ===============================================================================
echo                SENTINEL-X AI-POWERED INTRUSION DETECTION SOC
echo ===============================================================================
echo.

cd /d "%~dp0"

:: 1. Detect Python Virtual Environment
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
    set "ALEMBIC_EXE=%~dp0.venv\Scripts\alembic.exe"
    set "UVICORN_EXE=%~dp0.venv\Scripts\uvicorn.exe"
) else if exist "..\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0..\.venv\Scripts\python.exe"
    set "ALEMBIC_EXE=%~dp0..\.venv\Scripts\alembic.exe"
    set "UVICORN_EXE=%~dp0..\.venv\Scripts\uvicorn.exe"
) else (
    set "PYTHON_EXE=python"
    set "ALEMBIC_EXE=alembic"
    set "UVICORN_EXE=uvicorn"
)

:: 2. Ensure .env exists
if not exist ".env" (
    echo [!] No .env detected. Creating development configuration from .env.example...
    copy .env.example .env >nul
)

:: 3. Run Alembic database migrations
echo [*] Applying Alembic database migrations to head...
set "PYTHONPATH=%~dp0backend;%PYTHONPATH%"
cd /d "%~dp0backend"
"%ALEMBIC_EXE%" upgrade head
cd /d "%~dp0"

:: 4. Populate roles, administrator, and realistic telemetry (idempotent)
echo [*] Ensuring database telemetry and accounts are populated...
"%PYTHON_EXE%" scripts\seed_database.py
"%PYTHON_EXE%" scripts\create_admin.py
"%PYTHON_EXE%" scripts\demo_data.py

:: 5. Launch FastAPI Backend on port 8000
echo [*] Starting FastAPI Backend server on port 8000...
netstat -ano | findstr :8000 >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    start "Sentinel-X Backend (Port 8000)" cmd /k "cd /d ""%~dp0backend"" && set PYTHONPATH=.;%%PYTHONPATH%% && "%UVICORN_EXE%" app.main:app --reload --host 0.0.0.0 --port 8000"
) else (
    echo [i] Backend is already listening on port 8000.
)

:: 6. Launch Vite Frontend on port 5173
echo [*] Starting Vite Frontend server on port 5173...
netstat -ano | findstr :5173 >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    start "Sentinel-X Frontend (Port 5173)" cmd /k "cd /d ""%~dp0frontend"" && npm run dev -- --host 0.0.0.0 --port 5173"
) else (
    echo [i] Frontend is already listening on port 5173.
)

:: 7. Wait for servers to stabilize and launch browser
timeout /t 3 /nobreak >nul
start http://localhost:5173

echo.
echo ===============================================================================
echo                 SENTINEL-X LIVE DEMONSTRATION READY!
echo ===============================================================================
echo.
echo  * Frontend Dashboard:   http://localhost:5173
echo  * Backend Swagger Docs: http://localhost:8000/docs
echo.
echo  --- DEMO CREDENTIALS ---
echo  * Administrator: admin@sentinel.internal   / SentinelAdmin2026!
echo  * Security Analyst: analyst@sentinel.internal / SentinelAnalyst2026!
echo  * Auditor / Viewer: viewer@sentinel.internal  / SentinelViewer2026!
echo.
echo ===============================================================================
echo Press any key to close this launcher window (servers will remain running).
pause >nul
