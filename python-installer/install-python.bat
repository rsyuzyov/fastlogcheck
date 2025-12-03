@echo off
REM Универсальный скрипт проверки и установки Python для Windows
REM Версия: 1.6.0
REM Использование: install-python.bat [/mode user|system]
REM   /mode user   - Автоматическая установка для текущего пользователя
REM   /mode system - Автоматическая установка для всех пользователей (требует права администратора)
REM   Без параметров - Интерактивный режим
REM Exit codes: 0 = Python готов к работе, 1 = Ошибка

chcp 65001 > nul

REM Сохранение полного пути к скрипту ДО enabledelayedexpansion
set "SELF_PATH=%~f0"

setlocal

REM Проверка параметров
set "MODE="
set "AUTO_CONFIRM=0"

REM Обработка всех параметров
:parse_args
if "%~1"=="" goto :args_done

REM Поддержка формата /mode=value
set "ARG=%~1"
if /i "%ARG:~0,6%"=="/mode=" (
    set "MODE=%ARG:~6%"
    shift
    goto :parse_args
)
if /i "%ARG:~0,6%"=="-mode=" (
    set "MODE=%ARG:~6%"
    shift
    goto :parse_args
)

REM Поддержка формата /mode value
if /i "%~1"=="/mode" (
    set "MODE=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="-mode" (
    set "MODE=%~2"
    shift
    shift
    goto :parse_args
)

shift
goto :parse_args
:args_done

REM Настройка параметров в зависимости от режима
if /i "%MODE%"=="user" (
    set "INSTALL_TYPE=1"
    set "AUTO_CONFIRM=1"
)
if /i "%MODE%"=="system" (
    set "INSTALL_TYPE=2"
    set "INSTALL_FOR_ALL=1"
    set "NEED_ADMIN=1"
    set "AUTO_CONFIRM=1"
)

REM [Шаг 1] Проверка Python в PATH
python --version >nul 2>&1
if %errorlevel% equ 0 (
    exit /b 0
)

REM [Шаг 2] Поиск Python в стандартных местах
set "PYTHON_FOUND=0"
set "PYTHON_PATH="

REM Проверка стандартных путей
set "SEARCH_PATHS=C:\Python314;C:\Python313;C:\Python312;C:\Python311;C:\Program Files\Python314;C:\Program Files\Python313;C:\Program Files\Python312;%LOCALAPPDATA%\Programs\Python\Python314;%LOCALAPPDATA%\Programs\Python\Python313;%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.14_qbz5n2kfra8p0;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0"

for %%P in (%SEARCH_PATHS%) do (
    if exist "%%P\python.exe" (
        "%%P\python.exe" --version >nul 2>&1
        if errorlevel 1 (
            REM Ничего не делаем
        ) else (
            set "PYTHON_PATH=%%P"
            set "PYTHON_FOUND=1"
        )
    )
)

if "%PYTHON_FOUND%"=="1" (
    if "%AUTO_CONFIRM%"=="1" (
        set "ADD_TO_PATH=Y"
    ) else (
        set /p "ADD_TO_PATH=Добавить найденный Python в PATH? (Y/N): "
    )

    if /i "%ADD_TO_PATH%"=="Y" (
        REM Добавление в PATH для текущего пользователя через setx
        setx PATH "%PYTHON_PATH%;%PYTHON_PATH%\Scripts;%PATH%" >nul 2>&1

        REM Обновление PATH для текущей сессии
        set "PATH=%PYTHON_PATH%;%PYTHON_PATH%\Scripts;%PATH%"

        python --version >nul 2>&1

        if errorlevel 1 (
            REM Продолжаем установку
        ) else (
            exit /b 0
        )
    )
)

REM [Шаг 3] Выбор типа установки
if "%AUTO_CONFIRM%"=="0" (
    set "INSTALL_FOR_ALL=0"
    set "NEED_ADMIN=0"

    REM Интерактивный режим
    echo Python не установлен, выберите тип установки:
    echo ^[1^] Для текущего пользователя ^(рекомендуется^)
    echo ^[2^] Для всех пользователей
    set /p "INSTALL_TYPE=Ваш выбор (1 или 2, Enter = 1): "
)

REM По умолчанию - для текущего пользователя
if "%INSTALL_TYPE%"=="" set "INSTALL_TYPE=1"

if "%INSTALL_TYPE%"=="2" (
    set "INSTALL_FOR_ALL=1"
    set "NEED_ADMIN=1"
)

:admin_check
REM [Шаг 4] Проверка прав администратора (если нужно)
if "%NEED_ADMIN%"=="1" (
    net session >nul 2>&1
    if errorlevel 1 (
        echo Запрос прав администратора для установки...

        REM Перезапуск с правами администратора с параметром /mode system
        REM Подавляем вывод ошибок, если пользователь отменит UAC
        powershell -Command "& {Start-Process -FilePath '%SELF_PATH%' -ArgumentList '/mode','system' -Verb RunAs}" 2>nul
        
        REM Безусловно завершаемся после показа UAC-диалога
        REM Если пользователь одобрит - запустится новый экземпляр с правами
        REM Если отменит - просто выходим, родительский скрипт получит ошибку
        exit /b 1
    )
)

REM [Шаг 5] Определение архитектуры системы
set "ARCH=x64"
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "ARCH=x64"
if "%PROCESSOR_ARCHITECTURE%"=="x86" set "ARCH=x86"
if "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"

REM [Шаг 6] Определение версии Python
set "PYTHON_VERSION=3.14.0"
set "PYTHON_MAJOR=3.14"

REM [Шаг 8] Попытка установки через winget
winget --version >nul 2>&1
if %errorlevel% equ 0 (
    echo Установка Python, пожалуйста подождите...
    echo.

    if "%INSTALL_FOR_ALL%"=="1" (
        REM Для всех пользователей
        winget install Python.Python.3.14 --scope machine --silent --accept-package-agreements --accept-source-agreements
    ) else (
        REM Для текущего пользователя
        winget install Python.Python.3.14 --scope user --silent --accept-package-agreements --accept-source-agreements
    )

    if %errorlevel% equ 0 (
        echo
        echo ✅ Python установлен через winget
        goto :verify_installation
    )
)

REM Альтернативный метод: скачивание установщика
set "DOWNLOAD_URL="
if "%ARCH%"=="x64" set "DOWNLOAD_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-amd64.exe"
if "%ARCH%"=="x86" set "DOWNLOAD_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%.exe"
if "%ARCH%"=="arm64" set "DOWNLOAD_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-arm64.exe"

set "INSTALLER_PATH=%TEMP%\python-installer.exe"

echo Скачивание установщика, пожалуйста подождите...
echo.

powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; try { Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%INSTALLER_PATH%' -UseBasicParsing; exit 0 } catch { Write-Host 'Ошибка скачивания:' $_.Exception.Message; exit 1 }}"

if %errorlevel% neq 0 (
    echo ❌ Ошибка скачивания установщика
    echo Попробуйте установить Python вручную:
    echo   1. Перейдите на https://www.python.org/downloads/
    echo   2. Скачайте Python %PYTHON_VERSION% или новее
    echo   3. Запустите установщик с опцией "Add Python to PATH"
    exit /b 1
)

REM Установка Python
echo Установка Python, пожалуйста подождите...

if "!INSTALL_FOR_ALL!"=="1" (
    "%INSTALLER_PATH%" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=1 SimpleInstall=1
) else (
    "%INSTALLER_PATH%" /quiet InstallAllUsers=0 PrependPath=1 Include_test=0 Include_launcher=1 SimpleInstall=1
)

if %errorlevel% neq 0 (
    echo ❌ Ошибка установки Python
    echo Код ошибки: %errorlevel%

    REM Попытка удаления частично установленного Python
    if exist "%INSTALLER_PATH%" (
        "%INSTALLER_PATH%" /uninstall /quiet
    )

    REM Удаление установщика
    del /f /q "%INSTALLER_PATH%" >nul 2>&1

    echo Рекомендуется установить Python вручную:
    echo   https://www.python.org/downloads/
    
    exit /b 1
)

echo ✅ Python установлен

REM Очистка
del /f /q "%INSTALLER_PATH%" >nul 2>&1

:verify_installation

REM [Шаг 9] Проверка установки и настройка PATH
REM Обновление PATH для текущей сессии
call :RefreshEnv

REM Небольшая задержка
timeout /t 2 /nobreak >nul

REM Проверка Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    REM Поиск Python снова с расширенными путями
    set "EXTENDED_PATHS=C:\Python314;C:\Python313;C:\Python312;C:\Program Files\Python314;C:\Program Files\Python313;%LOCALAPPDATA%\Programs\Python\Python314;%LOCALAPPDATA%\Programs\Python\Python313;%LOCALAPPDATA%\Microsoft\WindowsApps;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.14_qbz5n2kfra8p0;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0"

    for %%P in (!EXTENDED_PATHS!) do (
        if exist "%%P\python.exe" (
            "%%P\python.exe" --version >nul 2>&1
            if !errorlevel! equ 0 (
                set "PATH=%%P;%%P\Scripts;%PATH%"

                REM Проверка снова
                "%%P\python.exe" --version >nul 2>&1
                if !errorlevel! equ 0 (
                    goto :check_pip
                )
            )
        )
    )

    echo ❌ Не удалось найти Python после установки
    echo Попробуйте закрыть и открыть новую командную строку
    exit /b 1
)

:check_pip

REM Проверка pip
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    python -m ensurepip --upgrade >nul 2>&1
)

exit /b 0

REM ===== Функция обновления переменных окружения =====
:RefreshEnv
echo Обновление PATH в текущем сеансе...
REM Обновление PATH из реестра (системный и пользовательский)
for /f "tokens=2*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul ^| findstr /i "PATH"') do set "SYS_PATH=%%B"
for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v PATH 2^>nul ^| findstr /i "PATH"') do set "USER_PATH=%%B"

REM Объединяем системный и пользовательский PATH
if defined USER_PATH (
    set "PATH=%SYS_PATH%;%USER_PATH%"
) else (
    set "PATH=%SYS_PATH%"
)

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

echo PATH обновлён из реестра
exit /b 0
