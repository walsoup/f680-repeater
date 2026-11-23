@echo off
setlocal
cd /d "%~dp0"

set PY=
where py >nul 2>&1
if not errorlevel 1 set PY=py -3
if not defined PY (
    where python >nul 2>&1
    if not errorlevel 1 set PY=python
)
if not defined PY (
    echo.
    echo Python 3 is required. Install it from https://www.python.org/downloads/
    echo and run this file again.
    pause
    goto :eof
)

if "%1"=="--serve-only" (
    %PY% tools\serve.py
    goto :eof
)

%PY% -c "import requests, Crypto" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing Python dependencies ^(requests, pycryptodome^) ...
    %PY% -m pip install --user -r requirements.txt
    if errorlevel 1 (
        echo [-] pip install failed. Install manually:
        echo     %PY% -m pip install -r requirements.txt
        pause
        goto :eof
    )
)

%PY% tools\onboard.py %*
