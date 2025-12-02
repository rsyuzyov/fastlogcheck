@echo off
REM Универсальный скрипт проверки и установки Python для Windows
REM Версия: 1.3.0
REM Использование: install-python.bat [/quiet]
REM   /quiet - Тихая установка без запросов (для текущего пользователя)
REM Exit codes: 0 = Python готов к работе, 1 = Ошибка

chcp 65001 > nul
setlocal enabledelayedexpansion

REM Проверка параметра /quiet
set "QUIET_MODE=0"
if /i "%~1"=="/quiet" set "QUIET_MODE=1"
if /i "%~1"=="-quiet" set "QUIET_MODE=1"

if "%QUIET_MODE%"=="1" (
    set "CALLED_FROM_PARENT=1"
) else (
    cls
)

echo ========================================
echo Проверка и установка Python
echo ========================================
echo.

REM [Шаг 1] Проверка Python в PATH
echo [1/9] Проверка Python в PATH...

python --version >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=2" %%i in ('python --version 2^>^&1') do set FOUND_VERSION=%%i
    echo ✅ Python !FOUND_VERSION! найден в PATH
    echo.
    echo Python готов к работе!
    echo.

    if "%CALLED_FROM_PARENT%"=="1" (
        exit /b 0
    )
    pause
    exit /b 0
)

echo ⚠️  Python не найден в PATH
echo.

REM [Шаг 2] Поиск Python в стандартных местах
echo [2/9] Поиск Python в стандартных местах...
echo.

set "PYTHON_FOUND=0"
set "PYTHON_PATH="

REM Проверка стандартных путей
set "SEARCH_PATHS=C:\Python314;C:\Python313;C:\Python312;C:\Python311;C:\Program Files\Python314;C:\Program Files\Python313;C:\Program Files\Python312;%LOCALAPPDATA%\Programs\Python\Python314;%LOCALAPPDATA%\Programs\Python\Python313;%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.14_qbz5n2kfra8p0;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0"

for %%P in (%SEARCH_PATHS%) do (
    if exist "%%P\python.exe" (
        "%%P\python.exe" --version >nul 2>&1
        if !errorlevel! equ 0 (
            echo ✅ Найден: %%P\python.exe
            set "PYTHON_PATH=%%P"
            set "PYTHON_FOUND=1"

            for /f "tokens=2" %%V in ('"%%P\python.exe" --version 2^>^&1') do (
                echo    Версия: %%V
            )
        )
    )
)

if "%PYTHON_FOUND%"=="1" (
    echo.
    echo Python найден, но не добавлен в PATH
    echo.

    if "%QUIET_MODE%"=="1" (
        set "ADD_TO_PATH=Y"
        echo ✅ Тихий режим: автоматическое добавление в PATH
    ) else (
        set /p "ADD_TO_PATH=Добавить найденный Python в PATH? (Y/N): "
    )

    if /i "!ADD_TO_PATH!"=="Y" (
        echo.
        echo Добавление Python в PATH...

        REM Добавление в PATH для текущего пользователя через setx
        setx PATH "%PYTHON_PATH%;%PYTHON_PATH%\Scripts;%PATH%" >nul 2>&1

        REM Обновление PATH для текущей сессии
        set "PATH=%PYTHON_PATH%;%PYTHON_PATH%\Scripts;%PATH%"

        echo ✅ Python добавлен в PATH
        echo.
        echo Проверка доступности...
        python --version

        if !errorlevel! equ 0 (
            echo.
            echo ========================================
            echo ✅ Python настроен и готов к работе!
            echo ========================================
            echo.

            if "%CALLED_FROM_PARENT%"=="1" (
                exit /b 0
            )
            pause
            exit /b 0
        )
    )
    echo.
)

echo Python не найден в стандартных местах
echo Требуется установка Python
echo.

REM [Шаг 3] Выбор типа установки
echo [3/9] Выбор типа установки...
echo.

set "INSTALL_FOR_ALL=0"
set "NEED_ADMIN=0"

if "%QUIET_MODE%"=="1" (
    REM Тихий режим - всегда для текущего пользователя
    set "INSTALL_TYPE=1"
    echo ✅ Тихий режим: установка для текущего пользователя
    echo.
) else (
    REM Интерактивный режим
    echo Выберите тип установки:
    echo.
    echo   [1] Для текущего пользователя (рекомендуется)
    echo       - Не требует прав администратора
    echo       - Устанавливается в: %LOCALAPPDATA%\Programs\Python
    echo       - Доступен только для вашей учетной записи
    echo.
    echo   [2] Для всех пользователей
    echo       - Требует права администратора
    echo       - Устанавливается в: C:\Program Files\Python313
    echo       - Доступен для всех пользователей системы
    echo.
    set /p "INSTALL_TYPE=Ваш выбор (1 или 2, Enter = 1): "

    REM По умолчанию - для текущего пользователя
    if "!INSTALL_TYPE!"=="" set "INSTALL_TYPE=1"

    echo.

    if "!INSTALL_TYPE!"=="2" (
        set "INSTALL_FOR_ALL=1"
        set "NEED_ADMIN=1"
        echo ✅ Выбрана установка для всех пользователей
    ) else (
        echo ✅ Выбрана установка для текущего пользователя
    )
    echo.
)

REM [Шаг 4] Проверка прав администратора (если нужно)
if "%NEED_ADMIN%"=="1" (
    echo [4/9] Проверка прав администратора...
    net session >nul 2>&1
    if !errorlevel! neq 0 (
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
) else (
    echo [4/9] Права администратора не требуются
    echo ✅ Установка для текущего пользователя
    echo.
)

REM [Шаг 5] Определение архитектуры системы
echo [5/9] Определение архитектуры системы...

set "ARCH=x64"
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "ARCH=x64"
if "%PROCESSOR_ARCHITECTURE%"=="x86" set "ARCH=x86"
if "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"

echo ✅ Архитектура: %ARCH%
echo.

REM [Шаг 6] Определение версии Python
echo [6/9] Определение версии Python для установки...

set "PYTHON_VERSION=3.14.0"
set "PYTHON_MAJOR=3.14"

echo ✅ Будет установлен Python %PYTHON_VERSION%
echo.

REM [Шаг 7] Запрос подтверждения у пользователя
echo [7/9] Подтверждение установки...
echo.
echo ========================================
echo.
echo Параметры установки:
echo   • Версия: Python %PYTHON_VERSION%
if "%INSTALL_FOR_ALL%"=="1" (
    echo   • Установка: Для всех пользователей
    echo   • Путь: C:\Program Files\Python314
) else (
    echo   • Установка: Для текущего пользователя
    echo   • Путь: %LOCALAPPDATA%\Programs\Python\Python314
)
echo   • PATH: Будет добавлен автоматически
echo   • Размер: ~30-40 МБ
echo.

if "%QUIET_MODE%"=="1" (
    echo ✅ Тихий режим: установка без подтверждения
    echo.
) else (
    set /p "CONFIRM=Установить Python? (Y/N): "

    if /i not "!CONFIRM!"=="Y" (
        echo.
        echo ❌ Установка отменена пользователем
        echo.
        if not "%CALLED_FROM_PARENT%"=="1" pause
        exit /b 1
    )

    echo.
    echo ✅ Подтверждение получено
    echo.
)

REM [Шаг 8] Попытка установки через winget
echo [8/9] Попытка установки через winget...

winget --version >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ winget обнаружен, начинаем установку...
    echo.
    echo Это может занять несколько минут...
    echo.

    if "%INSTALL_FOR_ALL%"=="1" (
        REM Для всех пользователей
        winget install Python.Python.3.14 --scope machine --silent --accept-package-agreements --accept-source-agreements
    ) else (
        REM Для текущего пользователя
        winget install Python.Python.3.14 --scope user --silent --accept-package-agreements --accept-source-agreements
    )

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
echo Скачивание официального установщика Python...

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
    if not "%CALLED_FROM_PARENT%"=="1" pause
    exit /b 1
)

echo ✅ Установщик скачан
echo.

REM Установка Python
echo Установка Python %PYTHON_VERSION%...
echo.
echo Выполняется установка, пожалуйста подождите...
echo Это может занять 2-5 минут...
echo.

if "%INSTALL_FOR_ALL%"=="1" (
    "%INSTALLER_PATH%" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=1 SimpleInstall=1
) else (
    "%INSTALLER_PATH%" /quiet InstallAllUsers=0 PrependPath=1 Include_test=0 Include_launcher=1 SimpleInstall=1
)

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
    if not "%CALLED_FROM_PARENT%"=="1" pause
    exit /b 1
)

echo ✅ Python установлен
echo.

REM Очистка
del /f /q "%INSTALLER_PATH%" >nul 2>&1

:verify_installation

REM [Шаг 9] Проверка установки и настройка PATH
echo [9/9] Проверка установки и настройка PATH...
echo.
echo Обновление переменных окружения...
echo.

REM Обновление PATH для текущей сессии
call :RefreshEnv

REM Небольшая задержка
timeout /t 2 /nobreak >nul

REM Проверка Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  Python установлен, но недоступен в PATH
    echo.
    echo Попытка найти Python и настроить PATH...
    echo.

    REM Поиск Python снова с расширенными путями
    set "EXTENDED_PATHS=C:\Python314;C:\Python313;C:\Python312;C:\Program Files\Python314;C:\Program Files\Python313;%LOCALAPPDATA%\Programs\Python\Python314;%LOCALAPPDATA%\Programs\Python\Python313;%LOCALAPPDATA%\Microsoft\WindowsApps;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.14_qbz5n2kfra8p0;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0"

    for %%P in (!EXTENDED_PATHS!) do (
        if exist "%%P\python.exe" (
            "%%P\python.exe" --version >nul 2>&1
            if !errorlevel! equ 0 (
                echo ✅ Найден: %%P\python.exe
                set "PATH=%%P;%%P\Scripts;%PATH%"

                REM Проверка снова
                "%%P\python.exe" --version >nul 2>&1
                if !errorlevel! equ 0 (
                    for /f "tokens=2" %%V in ('"%%P\python.exe" --version 2^>^&1') do (
                        echo ✅ Python %%V успешно настроен для текущей сессии
                    )
                    goto :check_pip
                )
            )
        )
    )

    echo.
    echo ⚠️  Python установлен, но требуется перезапуск терминала
    echo.
    echo Пожалуйста:
    echo   1. Закройте это окно
    echo   2. Откройте новую командную строку
    echo   3. Python будет доступен автоматически
    echo.
    if not "%CALLED_FROM_PARENT%"=="1" pause
    exit /b 0
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set INSTALLED_VERSION=%%i
echo ✅ Python %INSTALLED_VERSION% успешно установлен и доступен
echo.

:check_pip

REM Проверка pip
python -m pip --version >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ pip доступен
) else (
    echo ⚠️  pip не найден, выполняется установка...
    python -m ensurepip --upgrade >nul 2>&1

    if !errorlevel! equ 0 (
        echo ✅ pip установлен
    )
)

echo.
echo ========================================
echo ✅ Python готов к работе!
echo ========================================
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
