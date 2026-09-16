@echo off
setlocal enabledelayedexpansion

echo.
echo  ============================================================
echo   Scrutics AI Setup
echo  ============================================================
echo.
echo  This script sets up the AI assistant for Scrutics.
echo  It will ask for your API key and configure everything
echo  automatically. You will not need to edit any files manually.
echo.
echo  ------------------------------------------------------------
echo   Which AI provider do you want to use?
echo  ------------------------------------------------------------
echo.
echo    1. Google Gemini   (free tier available - recommended)
echo    2. OpenAI          (paid account required)
echo    3. Anthropic       (paid account required)
echo    4. Exit
echo.
set /p CHOICE="  Enter 1, 2, 3 or 4 and press Enter: "

if "%CHOICE%"=="4" goto :done
if "%CHOICE%"=="1" (
    set "VAR_NAME=GEMINI_API_KEY"
    set "PROVIDER_LABEL=Google Gemini"
    set "KEY_URL=https://aistudio.google.com/app/apikey"
    set "YAML_PROVIDER=gemini"
    set "YAML_MODEL=gemini-2.0-flash"
    goto :get_key
)
if "%CHOICE%"=="2" (
    set "VAR_NAME=OPENAI_API_KEY"
    set "PROVIDER_LABEL=OpenAI"
    set "KEY_URL=https://platform.openai.com/api-keys"
    set "YAML_PROVIDER=openai"
    set "YAML_MODEL=gpt-4o-mini"
    goto :get_key
)
if "%CHOICE%"=="3" (
    set "VAR_NAME=ANTHROPIC_API_KEY"
    set "PROVIDER_LABEL=Anthropic"
    set "KEY_URL=https://console.anthropic.com/settings/keys"
    set "YAML_PROVIDER=anthropic"
    set "YAML_MODEL=claude-haiku-4-5"
    goto :get_key
)

echo  Invalid choice. Run the script again and enter 1, 2, 3 or 4.
goto :done

:get_key
echo.
echo  Get your !PROVIDER_LABEL! API key from:
echo    !KEY_URL!
echo.
echo  Paste the key below and press Enter.
echo  (It will be visible on screen - close this window after.)
echo.
set /p USER_KEY="  API key: "

if "!USER_KEY!"=="" (
    echo.
    echo  No key entered. Nothing was changed.
    goto :done
)

echo.
echo  Setting up Scrutics AI...

:: Save key as a permanent Windows user environment variable
powershell -NoProfile -Command "[System.Environment]::SetEnvironmentVariable('!VAR_NAME!', '!USER_KEY!', 'User')" >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ERROR: Could not save the environment variable.
    echo  Try right-clicking this script and choosing "Run as administrator".
    goto :done
)

:: Also set it in the current process so the YAML write below can verify it
set "!VAR_NAME!=!USER_KEY!"

:: Write user config to %USERPROFILE%\.scrutics\ai.yaml — never overwrite the packaged template
set "YAML_PATH=%USERPROFILE%\.scrutics\ai.yaml"
if not exist "%USERPROFILE%\.scrutics" mkdir "%USERPROFILE%\.scrutics"
)

:: Write ai.yaml using Python (already required by Scrutics, handles encoding reliably)
python -c "import sys; p,m,v = sys.argv[1],sys.argv[2],sys.argv[3]; open(sys.argv[4],'w',encoding='utf-8').write('# Scrutics AI Configuration\n# Configured automatically by scrutics_ai_setup.bat\n# To reconfigure, run scrutics_ai_setup.bat again.\nenabled: true\nprovider: '+p+'\nmodel: '+m+'\napi_key: ${'+v+'}\ntemperature: 0.3\nmax_tokens: 1024\ntimeout: 60\n')" "!YAML_PROVIDER!" "!YAML_MODEL!" "!VAR_NAME!" "!YAML_PATH!" 2>nul

if errorlevel 1 (
    echo.
    echo  WARNING: Could not write ai.yaml automatically.
    goto :show_manual
)

echo.
echo  ============================================================
echo   All done! Scrutics AI is ready to use.
echo  ============================================================
echo.
echo  Provider : !PROVIDER_LABEL!
echo  Model    : !YAML_MODEL!
echo.
echo  Start Scrutics and press A to open the AI assistant.
echo  Or from the terminal: scrutics ai "What is on this network?"
echo.
echo  NOTE FOR WSL2 USERS:
echo  The key was saved for Windows. To use it in your Linux
echo  terminal (WSL2), run this command once:
echo.
echo    export !VAR_NAME!=!USER_KEY!
echo.
echo  To make it permanent in Linux, add that line to ~/.bashrc
echo.
echo  ------------------------------------------------------------
echo  Close this window now - your key is visible above.
echo  ------------------------------------------------------------
echo.
goto :done

:show_manual
echo.
echo  Could not write ai.yaml automatically. Create it manually at:
echo    %USERPROFILE%\.scrutics\ai.yaml
echo.
echo.
echo    enabled: true
echo    provider: !YAML_PROVIDER!
echo    model: !YAML_MODEL!
echo    api_key: ${!VAR_NAME!}
echo    temperature: 0.3
echo    max_tokens: 1024
echo    timeout: 60
echo.

:done
endlocal
pause
