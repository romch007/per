@echo off
setlocal enabledelayedexpansion

rem =======================================
rem Configuration
rem =======================================
set SOLUTION_PATH=%~dp0PERDriver.sln
set CONFIGURATION=Release
set PLATFORM=x64

rem Locate MSBuild
set MSBUILD_PATH=
for /f "tokens=*" %%i in ('where msbuild 2^>nul') do set MSBUILD_PATH=%%i

if "%MSBUILD_PATH%"=="" (
    echo [ERROR] MSBuild not found in PATH. Please run from a Developer Command Prompt or set the path manually.
    exit /b 1
)

echo =======================================
echo Building %SOLUTION_PATH%
echo Configuration: %CONFIGURATION%
echo Platform: %PLATFORM%
echo =======================================

MSBuild.exe /m /p:Configuration=%CONFIGURATION% /p:Platform=%PLATFORM% "%SOLUTION_PATH%"

if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
    exit /b %errorlevel%
) else (
    echo [SUCCESS] Build completed successfully.
)

endlocal