@echo off
setlocal EnableExtensions

REM ============================================================================
REM run.cmd - Avvia il connettore AD (mwa-ad-connector) in locale.
REM
REM Uso:
REM   run.cmd                 -> usa l'env di default sotto ENVFILE
REM   run.cmd <percorso.ps1>  -> usa un file env alternativo
REM
REM Prerequisiti: il PC deve raggiungere il DC (LDAPS 636), il trust store PEM
REM deve esistere, e il file env deve contenere i valori reali del dominio.
REM ============================================================================

REM --- Configurazione (modifica qui se cambi percorsi) ------------------------
set "REPO=C:\Users\d.tortorici\Projects\M365 Agents\activeconnector"
set "ENVFILE=C:\ProgramData\MWA\mwa-ad-env.ps1"
set "HOST=127.0.0.1"
set "PORT=8443"

REM --- Override del file env via argomento (opzionale) ------------------------
if not "%~1"=="" set "ENVFILE=%~1"

echo ============================================================================
echo  MWA AD Connector - avvio locale
echo    repo   : %REPO%
echo    env    : %ENVFILE%
echo    ascolta: http://%HOST%:%PORT%
echo ============================================================================

REM --- Preflight --------------------------------------------------------------
where uv >nul 2>&1
if errorlevel 1 (
  echo [ERRORE] 'uv' non trovato nel PATH. Installa uv: https://astral.sh/uv
  exit /b 1
)

if not exist "%REPO%\pyproject.toml" (
  echo [ERRORE] Repo connettore non trovato: %REPO%
  exit /b 1
)

if not exist "%ENVFILE%" (
  echo [ERRORE] File env non trovato: %ENVFILE%
  echo          Genera la configurazione con scripts\discover_ad_env.ps1
  echo          oppure passa il percorso corretto: run.cmd ^<file.ps1^>
  exit /b 1
)

cd /d "%REPO%"
if errorlevel 1 (
  echo [ERRORE] Impossibile entrare in: %REPO%
  exit /b 1
)

REM --- 1) Dipendenze ----------------------------------------------------------
echo.
echo [1/2] Sincronizzo le dipendenze (uv sync)...
uv sync
if errorlevel 1 (
  echo [ERRORE] 'uv sync' fallito.
  exit /b 1
)

REM --- 2) Carica l'env nella sessione PowerShell e avvia il connettore ---------
echo.
echo [2/2] Avvio connettore (CTRL+C per fermare)...
echo       Health: http://%HOST%:%PORT%/api/v1/health
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command ". '%ENVFILE%'; uv run python -m mwa_ad_connector.entrypoints.api"

endlocal
