@echo off
REM Скрипт установки зависимостей для Server Logs Analysis Tool
REM Windows Batch version

setlocal enabledelayedexpansion
chcp 65001 > nul
cls

echo ================================
echo Server Logs Analysis Tool
echo Установка зависимостей
echo ================================
echo.

REM Проверка Python версии
echo [1/4] Проверка версии Python...

python --version > nul 2>&1
if errorlevel 1 (
    echo ❌ Python не найден или не добавлен в PATH
    echo.
    echo ========================================
    echo Автоматическая установка Python
    echo ========================================
    echo.
    echo У вас есть два варианта:
    echo.
    echo   [1] Автоматическая установка (рекомендуется)
    echo       - Скачивание и установка последней версии Python
    echo       - Автоматическая настройка PATH
    echo       - Требует прав администратора
    echo.
    echo   [2] Ручная установка
    echo       - Инструкции по установке вручную
    echo.
    set /p "INSTALL_CHOICE=Выберите вариант (1 или 2): "
    echo.

    if "!INSTALL_CHOICE!"=="1" (
        echo Запуск автоматической установки Python...
        echo.

        REM Устанавливаем флаг, что скрипт вызван из install.bat
        set "CALLED_FROM_PARENT=1"

        REM Запускаем скрипт установки Python
        call "%~dp0python-installer\install-python.bat"

        REM Проверяем результат
        if errorlevel 1 (
            echo.
            echo ❌ Автоматическая установка не удалась
            echo.
            echo Попробуйте установить Python вручную:
            echo   1. Перейдите на https://www.python.org/downloads/
            echo   2. Скачайте установщик Python 3.11 или новее
            echo   3. При установке ОБЯЗАТЕЛЬНО отметьте:
            echo      ✓ Add Python to PATH
            echo   4. После установки перезапустите командную строку
            echo.
            pause
            exit /b 1
        )

        echo.
        echo ========================================
        echo Продолжение установки зависимостей...
        echo ========================================
        echo.

        REM Python установлен, продолжаем
    ) else (
        echo Для ручной установки Python:
        echo   1. Перейдите на https://www.python.org/downloads/
        echo   2. Скачайте установщик Python 3.11 или новее
        echo   3. При установке ОБЯЗАТЕЛЬНО отметьте:
        echo      ✓ Add Python to PATH
        echo   4. После установки перезапустите командную строку
        echo   5. Запустите install.bat снова
        echo.
        echo Альтернатива - установка через winget:
        echo   winget install Python.Python.3.13
        echo.
        pause
        exit /b 1
    )
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo ✅ Python %PYTHON_VERSION%
echo.

REM Проверка pip
echo [2/4] Проверка pip...

python -m pip --version > nul 2>&1
if errorlevel 1 (
    echo ❌ pip не найден
    echo.
    echo Установите pip: python -m ensurepip --upgrade
    pause
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
    pause
    exit /b 1
)

echo ✅ Зависимости установлены
echo.

REM Проверка установки
echo [4/4] Проверка установки...

python -c "import paramiko, jinja2" 2> nul
if errorlevel 1 (
    echo ❌ Ошибка импорта модулей
    pause
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
echo   python check_server_logs.py srv-hv1.ag.local
echo.
echo   # Несколько серверов
echo   python check_server_logs.py srv-hv1.ag.local srv-hv2.ag.local
echo.
echo Подробнее: см. README.md и USAGE.md
echo.

pause
