@echo off
setlocal
rem  Ferryman one-click setup for Windows.
rem
rem  Why a .cmd and not just install.ps1: a .ps1 cannot be double-clicked - Windows
rem  opens it in Notepad - and the documented alternative was pasting an `irm ... | iex`
rem  line into PowerShell. That is a command line, which is the thing this product
rem  promises its users they will not need. A .cmd runs on a double click on every
rem  Windows there is, with no execution-policy change and no administrator rights.
rem
rem  It does the whole job: installs ferry, points a folder at Ferryman, and opens the
rem  dashboard. After this the person is in a browser and never sees a terminal again.

title Ferryman setup
echo.
echo   Ferryman setup
echo   --------------
echo.

rem Install (or update) the binary. install.ps1 verifies the release checksum.
echo   Installing Ferryman...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { irm https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.ps1 | iex } catch { Write-Host $_.Exception.Message; exit 1 }"
if errorlevel 1 goto failed

set "FERRY=%LOCALAPPDATA%\Ferryman\bin\ferry.exe"
if not exist "%FERRY%" goto failed

rem `ferry enable` refuses without a contact address (LICENSE section 3), so ask for it
rem here rather than letting setup die on it. Found by running the mac/Linux twin of this
rem file end to end: a double click cannot pass a flag, so anything enable requires, this
rem has to collect.
echo.
echo   Your email address. Ferryman registers it and sends nothing else -
echo   PRIVACY.md lists the entire payload.
echo.
set "EMAIL="
set /p "EMAIL=Email: "
if not defined EMAIL (
  echo   An address is needed to enable a project. Nothing else is collected.
  goto failed
)

echo.
echo   Which folder holds the project you want Ferryman to coordinate?
echo   Drag the folder onto this window and press Enter, or press Enter to use
echo   the folder this file is in.
echo.
set "PROJECT=%~dp0"
set /p "PROJECT=Folder: "
rem Strip the quotes Windows adds when a folder is dragged in.
set PROJECT=%PROJECT:"=%
if not exist "%PROJECT%" (
  echo   That folder does not exist: %PROJECT%
  goto failed
)

echo.
echo   Setting up %PROJECT%
pushd "%PROJECT%"
"%FERRY%" enable --email "%EMAIL%"
if errorlevel 1 (
  popd
  goto failed
)

echo.
echo   Opening the dashboard. Leave this window open while you use it -
echo   closing it stops Ferryman.
echo.
"%FERRY%" dashboard
popd
goto done

:failed
echo.
echo   Setup did not finish. The message above says why.
echo   If you are stuck, open an issue: https://github.com/estejosh/ferryman/issues
echo.
pause
exit /b 1

:done
pause
