@echo off

REM This script creates a python virtual environment in the directory venv if non exists.
REM Then it installs all dependencies from requirements.in
REM The packages must be downloadable via pip or reside in the subdirectory packages.
REM If the requirements.in changes the update is performed accordingly.

setlocal
set "ERRORCODE=0"
set "BATCH_FILE=%~dp0%~nx0"
set "CURRENT_PATH=%~dp0"

set "VENV_SCRIPT=%CURRENT_PATH%pyvenv.py"
set "VENV_PATH=%CURRENT_PATH%venv\"
set "PYTHON_PATH=%VENV_PATH%Scripts\python.exe"
set "PYTHON_ACTIVATE=%VENV_PATH%Scripts\activate.bat"

py -3 %VENV_SCRIPT% --min-version 3.6 --path %VENV_PATH% || GOTO:ERROR

if exist "%PYTHON_ACTIVATE%" (
    GOTO:ACTIVATE
) else (
    echo missing %PYTHON_ACTIVATE%
)

:ERROR
set "ERRORCODE=1"

:END
REM pause only if run from explorer with doubleclick
echo %cmdcmdline% | findstr /ic:"%~f0" >nul && pause
endlocal && exit /b %ERRORCODE%

:ACTIVATE
REM open new console if run from explorer with doubleclick
endlocal && set "ACTIVATE_BAT=%PYTHON_ACTIVATE%"
call %ACTIVATE_BAT%
echo %cmdcmdline% | findstr /ic:"%~f0" >nul && start "Python virtual environment" cmd /k
