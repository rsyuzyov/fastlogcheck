@echo off
REM Универсальный скрипт проверки и установки Python для Windows
REM Версия: 1.5.0
REM Использование: install-python.bat [/quiet] [/for-all] [/verbose]
REM   /quiet - Тихая установка без запросов
REM   /for-all - Установка для всех пользователей (требует права администратора)
REM   /verbose - Детальный вывод всех шагов установки
REM Exit codes: 0 = Python готов к работе, 1 = Ошибка

chcp 65001 > nul
setlocal enabledelayedexpansion

REM Проверка параметров
set "QUIET_MODE=0"
set "FORCE_FOR_ALL=0"
set "VERBOSE_MODE=0"

REM Обработка всех параметров
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="/quiet" set "QUIET_MODE=1"
if /i "%~1"=="-quiet" set "QUIET_MODE=1"
if /i "%~1"=="/for-all" set "FORCE_FOR_ALL=1"
if /i "%~1"=="-for-all" set "FORCE_FOR_ALL=1"
if /i "%~1"=="/verbose" set "VERBOSE_MODE=1"
if /i "%~1"=="-verbose" set "VERBOSE_MODE=1"
shift
goto :parse_args
:args_done

if "%QUIET_MODE%"=="0" (
    cls
)

REM Вспомогательные команды для условного вывода
REM VECHO - вывод только в verbose режиме
REM ECHO_ALWAYS - вывод всегда
set "VECHO=if "%VERBOSE_MODE%"=="1" echo"
set "ECHO_ALWAYS=echo"

if "%VERBOSE_MODE%"=="1" (
    %ECHO_ALWAYS% ========================================
    %ECHO_ALWAYS% Проверка и установка Python
    %ECHO_ALWAYS% ========================================
    %ECHO_ALWAYS%.
)

REM [Шаг 1] Проверка Python в PATH
%VECHO% [1/9] Проверка Python в PATH...

python --version >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=2" %%i in ('python --version 2^>^&1') do set FOUND_VERSION=%%i
    %VECHO% ✅ Python !FOUND_VERSION! найден в PATH
    %VECHO%.
    %VECHO% Python готов к работе!
    %VECHO%.

    if "%QUIET_MODE%"=="0" (
        if "%VERBOSE_MODE%"=="1" pause
    )
    exit /b 0
)

%VECHO% ⚠️  Python не найден в PATH
%VECHO%.

REM [Шаг 2] Поиск Python в стандартных местах
%VECHO% [2/9] Поиск Python в стандартных местах...
%VECHO%.

set "PYTHON_FOUND=0"
set "PYTHON_PATH="

REM Проверка стандартных путей
set "SEARCH_PATHS=C:\Python314;C:\Python313;C:\Python312;C:\Python311;C:\Program Files\Python314;C:\Program Files\Python313;C:\Program Files\Python312;%LOCALAPPDATA%\Programs\Python\Python314;%LOCALAPPDATA%\Programs\Python\Python313;%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.14_qbz5n2kfra8p0;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0"

for %%P in (%SEARCH_PATHS%) do (
    if exist "%%P\python.exe" (
        "%%P\python.exe" --version >nul 2>&1
        if !errorlevel! equ 0 (
            %VECHO% ✅ Найден: %%P\python.exe
            set "PYTHON_PATH=%%P"
            set "PYTHON_FOUND=1"

            for /f "tokens=2" %%V in ('"%%P\python.exe" --version 2^>^&1') do (
                %VECHO%    Версия: %%V
            )
        )
    )
)

if "%PYTHON_FOUND%"=="1" (
    %VECHO%.
    %VECHO% Python найден, но не добавлен в PATH
    %VECHO%.

    if "%QUIET_MODE%"=="1" (
        set "ADD_TO_PATH=Y"
        %VECHO% ✅ Тихий режим: автоматическое добавление в PATH
    ) else (
        set /p "ADD_TO_PATH=Добавить найденный Python в PATH? (Y/N): "
    )

    if /i "!ADD_TO_PATH!"=="Y" (
        %VECHO%.
        %VECHO% Добавление Python в PATH...

        REM Добавление в PATH для текущего пользователя через setx
        setx PATH "%PYTHON_PATH%;%PYTHON_PATH%\Scripts;%PATH%" >nul 2>&1

        REM Обновление PATH для текущей сессии
        set "PATH=%PYTHON_PATH%;%PYTHON_PATH%\Scripts;%PATH%"

        %VECHO% ✅ Python добавлен в PATH
        %VECHO%.
        %VECHO% Проверка доступности...
        python --version >nul 2>&1

        if !errorlevel! equ 0 (
            %VECHO%.
            if "%VERBOSE_MODE%"=="1" (
                echo ========================================
                echo ✅ Python настроен и готов к работе!
                echo ========================================
                echo.
            )

            if "%QUIET_MODE%"=="0" (
                if "%VERBOSE_MODE%"=="1" pause
            )
            exit /b 0
        )
    )
    %VECHO%.
)

%VECHO% Python не найден в стандартных местах
%VECHO% Требуется установка Python
%VECHO%.

REM [Шаг 3] Выбор типа установки
%VECHO% [3/9] Выбор типа установки...
%VECHO%.

set "INSTALL_FOR_ALL=0"
set "NEED_ADMIN=0"

REM Проверка флага принудительной установки для всех
if "%FORCE_FOR_ALL%"=="1" (
    set "INSTALL_FOR_ALL=1"
    set "NEED_ADMIN=1"
    set "INSTALL_TYPE=2"
    %VECHO% ✅ Установка для всех пользователей (передано через параметр)
    %VECHO%.
) else if "%QUIET_MODE%"=="1" (
    REM Тихий режим - всегда для текущего пользователя
    set "INSTALL_TYPE=1"
    %VECHO% ✅ Тихий режим: установка для текущего пользователя
    %VECHO%.
) else (
    REM Интерактивный режим
    echo.
    echo Python не установлен, выберите тип установки:
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
        %VECHO% ✅ Выбрана установка для всех пользователей
    ) else (
        %VECHO% ✅ Выбрана установка для текущего пользователя
    )
    %VECHO%.
)

REM [Шаг 4] Проверка прав администратора (если нужно)
if "%NEED_ADMIN%"=="1" (
    %VECHO% [4/9] Проверка прав администратора...
    net session >nul 2>&1
    if !errorlevel! neq 0 (
        echo.
        echo Запрос прав администратора для установки...
        echo.

        REM Перезапуск с правами администратора с параметрами /quiet /for-all
        powershell -Command "Start-Process '%~f0' -ArgumentList '/quiet /for-all' -Verb RunAs"
        exit /b
    )
    %VECHO% ✅ Права администратора получены
    %VECHO%.
) else (
    %VECHO% [4/9] Права администратора не требуются
    %VECHO% ✅ Установка для текущего пользователя
    %VECHO%.
)

REM [Шаг 5] Определение архитектуры системы
%VECHO% [5/9] Определение архитектуры системы...

set "ARCH=x64"
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "ARCH=x64"
if "%PROCESSOR_ARCHITECTURE%"=="x86" set "ARCH=x86"
if "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"

%VECHO% ✅ Архитектура: %ARCH%
%VECHO%.

REM [Шаг 6] Определение версии Python
%VECHO% [6/9] Определение версии Python для установки...

set "PYTHON_VERSION=3.14.0"
set "PYTHON_MAJOR=3.14"

%VECHO% ✅ Будет установлен Python %PYTHON_VERSION%
%VECHO%.

REM [Шаг 7] Запрос подтверждения у пользователя
%VECHO% [7/9] Подтверждение установки...
if "%VERBOSE_MODE%"=="1" (
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
)

if "%QUIET_MODE%"=="1" (
    %VECHO% ✅ Тихий режим: установка без подтверждения
    %VECHO%.
) else (
    if "%VERBOSE_MODE%"=="0" (
        echo.
        echo Установка Python %PYTHON_VERSION%...
        echo.
    )
    set /p "CONFIRM=Установить Python? (Y/N): "

    if /i not "!CONFIRM!"=="Y" (
        echo.
        echo ❌ Установка отменена пользователем
        echo.
        if "%QUIET_MODE%"=="0" pause
        exit /b 1
    )

    echo.
    %VECHO% ✅ Подтверждение получено
    %VECHO%.
)

REM [Шаг 8] Попытка установки через winget
%VECHO% [8/9] Попытка установки через winget...

winget --version >nul 2>&1
if %errorlevel% equ 0 (
    %VECHO% ✅ winget обнаружен, начинаем установку...
    %VECHO%.
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
        echo.
        echo ✅ Python установлен через winget
        goto :verify_installation
    ) else (
        echo.
        %VECHO% ⚠️  winget не смог установить Python
        %VECHO% Переход к альтернативному методу...
        %VECHO%.
    )
) else (
    %VECHO% ⚠️  winget не найден, используем альтернативный метод
    %VECHO%.
)

REM Альтернативный метод: скачивание установщика
%VECHO% Скачивание официального установщика Python...

set "DOWNLOAD_URL="
if "%ARCH%"=="x64" set "DOWNLOAD_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-amd64.exe"
if "%ARCH%"=="x86" set "DOWNLOAD_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%.exe"
if "%ARCH%"=="arm64" set "DOWNLOAD_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-arm64.exe"

set "INSTALLER_PATH=%TEMP%\python-installer.exe"

%VECHO% Скачивание с: %DOWNLOAD_URL%
%VECHO% Сохранение в: %INSTALLER_PATH%
%VECHO%.
echo Скачивание установщика, пожалуйста подождите...
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
    if "%QUIET_MODE%"=="0" pause
    exit /b 1
)

%VECHO% ✅ Установщик скачан
%VECHO%.

REM Установка Python
%VECHO% Установка Python %PYTHON_VERSION%...
%VECHO%.
echo Установка Python, пожалуйста подождите...
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
    %VECHO% Выполняется откат...

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
    if "%QUIET_MODE%"=="0" pause
    exit /b 1
)

echo ✅ Python установлен
echo.

REM Очистка
del /f /q "%INSTALLER_PATH%" >nul 2>&1

:verify_installation

REM [Шаг 9] Проверка установки и настройка PATH
%VECHO% [9/9] Проверка установки и настройка PATH...
%VECHO%.
%VECHO% Обновление переменных окружения...
%VECHO%.

REM Обновление PATH для текущей сессии
call :RefreshEnv

REM Небольшая задержка
timeout /t 2 /nobreak >nul

REM Проверка Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    %VECHO% ⚠️  Python установлен, но недоступен в PATH
    %VECHO%.
    %VECHO% Попытка найти Python и настроить PATH...
    %VECHO%.

    REM Поиск Python снова с расширенными путями
    set "EXTENDED_PATHS=C:\Python314;C:\Python313;C:\Python312;C:\Program Files\Python314;C:\Program Files\Python313;%LOCALAPPDATA%\Programs\Python\Python314;%LOCALAPPDATA%\Programs\Python\Python313;%LOCALAPPDATA%\Microsoft\WindowsApps;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.14_qbz5n2kfra8p0;%LOCALAPPDATA%\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0"

    for %%P in (!EXTENDED_PATHS!) do (
        if exist "%%P\python.exe" (
            "%%P\python.exe" --version >nul 2>&1
            if !errorlevel! equ 0 (
                %VECHO% ✅ Найден: %%P\python.exe
                set "PATH=%%P;%%P\Scripts;%PATH%"

                REM Проверка снова
                "%%P\python.exe" --version >nul 2>&1
                if !errorlevel! equ 0 (
                    for /f "tokens=2" %%V in ('"%%P\python.exe" --version 2^>^&1') do (
                        %VECHO% ✅ Python %%V успешно настроен для текущей сессии
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
    if "%QUIET_MODE%"=="0" pause
    exit /b 0
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set INSTALLED_VERSION=%%i
%VECHO% ✅ Python %INSTALLED_VERSION% успешно установлен и доступен
%VECHO%.

:check_pip

REM Проверка pip
python -m pip --version >nul 2>&1
if %errorlevel% equ 0 (
    %VECHO% ✅ pip доступен
) else (
    %VECHO% ⚠️  pip не найден, выполняется установка...
    python -m ensurepip --upgrade >nul 2>&1

    if !errorlevel! equ 0 (
        %VECHO% ✅ pip установлен
    )
)

if "%VERBOSE_MODE%"=="1" (
    echo.
    echo ========================================
    echo ✅ Python готов к работе!
    echo ========================================
    echo.
)

if "%QUIET_MODE%"=="0" (
    if "%VERBOSE_MODE%"=="1" pause
)

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
