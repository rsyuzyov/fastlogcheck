@echo off
REM Универсальный скрипт автоматической установки Python для Windows
REM Версия: 1.0.0
REM Поддерживаемые системы: Windows 10+, Windows Server 2019+
REM Архитектуры: x86, x64, ARM64

chcp 65001 > nul
setlocal enabledelayedexpansion

cls

echo ========================================
echo Автоматическая установка Python
echo ========================================
echo.

REM Проверка прав администратора
echo [1/7] Проверка прав администратора...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  Требуются права администратора
    echo.
    echo Перезапуск с правами администратора...
    echo.

    REM Перезапуск с правами администратора
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
echo ✅ Права администратора получены
echo.

REM Определение архитектуры системы
echo [2/7] Определение архитектуры системы...

set "ARCH=x64"
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "ARCH=x64"
if "%PROCESSOR_ARCHITECTURE%"=="x86" set "ARCH=x86"
if "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"

echo ✅ Архитектура: %ARCH%
echo.

REM Определение последней версии Python 3.13.x
echo [3/7] Определение версии Python для установки...

set "PYTHON_VERSION=3.13.1"
set "PYTHON_MAJOR=3.13"

echo ✅ Будет установлен Python %PYTHON_VERSION%
echo.

REM Запрос подтверждения у пользователя
echo ========================================
echo.
echo Python не найден в системе.
echo.
echo Предлагается установить Python %PYTHON_VERSION% (%ARCH%)
echo.
echo Параметры установки:
echo   • Версия: Python %PYTHON_VERSION%
echo   • Установка: Для всех пользователей
echo   • PATH: Будет добавлен автоматически
echo   • Размер: ~30-40 МБ
echo.
set /p "CONFIRM=Установить Python? (Y/N): "

if /i not "%CONFIRM%"=="Y" (
    echo.
    echo ❌ Установка отменена пользователем
    echo.
    pause
    exit /b 1
)

echo.
echo ✅ Подтверждение получено
echo.

REM Попытка установки через winget
echo [4/7] Попытка установки через winget...

winget --version >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ winget обнаружен, начинаем установку...
    echo.
    echo Это может занять несколько минут...
    echo.

    winget install Python.Python.3.13 --silent --accept-package-agreements --accept-source-agreements

    if %errorlevel% equ 0 (
        echo.
        echo ✅ Python установлен через winget
        goto :verify_installation
    ) else (
        echo.
        echo ⚠️  winget не смог установить Python
        echo Переход к альтернативному методу...
        echo.
    )
) else (
    echo ⚠️  winget не найден, используем альтернативный метод
    echo.
)

REM Альтернативный метод: скачивание установщика
echo [5/7] Скачивание официального установщика Python...

set "DOWNLOAD_URL="
if "%ARCH%"=="x64" set "DOWNLOAD_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-amd64.exe"
if "%ARCH%"=="x86" set "DOWNLOAD_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%.exe"
if "%ARCH%"=="arm64" set "DOWNLOAD_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-arm64.exe"

set "INSTALLER_PATH=%TEMP%\python-installer.exe"

echo Скачивание с: %DOWNLOAD_URL%
echo Сохранение в: %INSTALLER_PATH%
echo.
echo Пожалуйста, подождите...
echo.

powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; try { Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%INSTALLER_PATH%' -UseBasicParsing; exit 0 } catch { Write-Host 'Ошибка скачивания:' $_.Exception.Message; exit 1 }}"

if %errorlevel% neq 0 (
    echo.
    echo ❌ Ошибка скачивания установщика
    echo.
    echo Попробуйте установить Python вручную:
    echo   1. Перейдите на https://www.python.org/downloads/
    echo   2. Скачайте Python %PYTHON_VERSION% или новее
    echo   3. Запустите установщик с опцией "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

echo ✅ Установщик скачан
echo.

REM Установка Python
echo [6/7] Установка Python %PYTHON_VERSION%...
echo.
echo Выполняется установка, пожалуйста подождите...
echo Это может занять 2-5 минут...
echo.

"%INSTALLER_PATH%" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=1 SimpleInstall=1

if %errorlevel% neq 0 (
    echo.
    echo ❌ Ошибка установки Python
    echo Код ошибки: %errorlevel%
    echo.
    echo Выполняется откат...

    REM Попытка удаления частично установленного Python
    if exist "%INSTALLER_PATH%" (
        "%INSTALLER_PATH%" /uninstall /quiet
    )

    REM Удаление установщика
    del /f /q "%INSTALLER_PATH%" >nul 2>&1

    echo.
    echo Рекомендуется установить Python вручную:
    echo   https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo ✅ Python установлен
echo.

REM Очистка
del /f /q "%INSTALLER_PATH%" >nul 2>&1

:verify_installation

REM Проверка установки
echo [7/7] Проверка установки...
echo.
echo Обновление переменных окружения...
echo.

REM Обновление PATH для текущей сессии
call :RefreshEnv

REM Проверка Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  Python установлен, но требуется перезапуск
    echo.
    echo Пожалуйста:
    echo   1. Закройте это окно
    echo   2. Откройте новую командную строку
    echo   3. Проверьте установку: python --version
    echo.
    pause
    exit /b 0
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set INSTALLED_VERSION=%%i
echo ✅ Python %INSTALLED_VERSION% успешно установлен и доступен
echo.

REM Проверка pip
python -m pip --version >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ pip доступен
) else (
    echo ⚠️  pip не найден, выполняется установка...
    python -m ensurepip --upgrade >nul 2>&1
)

echo.
echo ========================================
echo ✅ Установка Python завершена успешно!
echo ========================================
echo.
echo Python %INSTALLED_VERSION% установлен и готов к использованию
echo.

REM Если скрипт запущен из другого скрипта, вернуться туда
if "%CALLED_FROM_PARENT%"=="1" (
    exit /b 0
)

pause

exit /b 0

REM ===== Функция обновления переменных окружения =====
:RefreshEnv
REM Обновление PATH из реестра
for /f "skip=2 tokens=3*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "SYS_PATH=%%a %%b"
for /f "skip=2 tokens=3*" %%a in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "USER_PATH=%%a %%b"
set "PATH=%SYS_PATH%;%USER_PATH%"
exit /b 0
