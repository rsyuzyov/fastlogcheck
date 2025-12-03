@echo off
REM Скрипт установки зависимостей для Server Logs Analysis Tool
REM Windows Batch version

setlocal
chcp 65001 > nul

echo ================================
echo Fast Check Logs Tool
echo Установка зависимостей
echo ================================
echo.

REM Проверка и установка Python (если необходимо)
echo [1/4] Проверка Python...
echo.

REM Запускаем скрипт проверки/установки Python в автоматическом режиме
call "%~dp0python-installer\install-python.bat" /mode user

REM Проверяем результат
if errorlevel 1 (
    echo.
    echo ❌ Не удалось настроить Python
    echo.
    exit /b 1
)

REM Обновление PATH в текущей сессии после установки
call :RefreshPath

echo.
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo ✅ Python %PYTHON_VERSION% готов к работе
echo.

REM Проверка pip
echo [2/4] Проверка pip...

python -m pip --version > nul 2>&1
if errorlevel 1 (
    echo ❌ pip не найден
    echo.
    echo Установите pip: python -m ensurepip --upgrade
    exit /b 1
)

echo ✅ pip установлен
echo.

REM Установка зависимостей
echo [3/4] Установка зависимостей...

python -m pip install -q paramiko jinja2
if errorlevel 1 (
    echo ❌ Ошибка установки зависимостей
    echo.
    echo Попробуйте установить вручную:
    echo   python -m pip install paramiko jinja2
    exit /b 1
)

echo ✅ Зависимости установлены
echo.

REM Проверка установки
echo [4/4] Проверка установки...

python -c "import paramiko, jinja2" 2> nul
if errorlevel 1 (
    echo ❌ Ошибка импорта модулей
    exit /b 1
)

echo ✅ Все модули импортируются корректно
echo.

REM Создание директории для отчётов
if not exist "reports" (
    mkdir reports
    echo ✅ Создана директория .\reports\
)

echo ================================
echo ✅ Установка завершена успешно!
echo ================================
echo.
echo Примеры использования:
echo.
echo   # Базовая проверка
echo   python check_server_logs.py server1.example.com
echo.
echo   # Несколько серверов
echo   python check_server_logs.py server1.example.com server2.example.com
echo.
echo Подробнее: см. README.md и USAGE.md
echo.

exit /b 0

REM ===== Функция обновления переменных окружения =====
:RefreshPath
REM Обновление PATH из реестра
for /f "skip=2 tokens=3*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "SYS_PATH=%%a %%b"
for /f "skip=2 tokens=3*" %%a in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "USER_PATH=%%a %%b"
set "PATH=%SYS_PATH%;%USER_PATH%"

REM Добавим стандартные пути Python явно (на случай задержки обновления PATH)
set "PATH=%PATH%;C:\Python314;C:\Python314\Scripts"
set "PATH=%PATH%;C:\Python313;C:\Python313\Scripts"
set "PATH=%PATH%;C:\Program Files\Python314;C:\Program Files\Python314\Scripts"
set "PATH=%PATH%;C:\Program Files\Python313;C:\Program Files\Python313\Scripts"
set "PATH=%PATH%;%LOCALAPPDATA%\Programs\Python\Python314;%LOCALAPPDATA%\Programs\Python\Python314\Scripts"
set "PATH=%PATH%;%LOCALAPPDATA%\Programs\Python\Python313;%LOCALAPPDATA%\Programs\Python\Python313\Scripts"
set "PATH=%PATH%;%LOCALAPPDATA%\Microsoft\WindowsApps"
set "PATH=%PATH%;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.14_qbz5n2kfra8p0"
set "PATH=%PATH%;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0"

exit /b 0
