# Универсальный скрипт проверки и установки Python для Windows
# Версия: 1.3.0
# Использование: install-python.ps1 [-Quiet]
#   -Quiet - Тихая установка без запросов (для текущего пользователя)
# Exit codes: 0 = Python готов к работе, 1 = Ошибка

param(
    [switch]$Quiet
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

# Установка режима работы
if ($Quiet) {
    $env:CALLED_FROM_PARENT = "1"
}

# Цвета для вывода
function Write-Step {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

Clear-Host

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Проверка и установка Python" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# [Шаг 1] Проверка Python в PATH
Write-Step "[1/9] Проверка Python в PATH..."

try {
    $pythonVersion = & python --version 2>&1
    if ($LASTEXITCODE -eq 0 -and $pythonVersion -match "Python (\d+\.\d+\.\d+)") {
        $versionNumber = $Matches[1]
        Write-Success "Python $versionNumber найден в PATH"
        Write-Host ""
        Write-Host "Python готов к работе!" -ForegroundColor Green
        Write-Host ""

        if ($env:CALLED_FROM_PARENT -eq "1") {
            exit 0
        }
        Read-Host "Нажмите Enter для выхода"
        exit 0
    }
} catch {
    # Python не найден, продолжаем
}

Write-Warning "Python не найден в PATH"
Write-Host ""

# [Шаг 2] Поиск Python в стандартных местах
Write-Step "[2/9] Поиск Python в стандартных местах..."
Write-Host ""

$pythonFound = $false
$pythonPath = ""

$searchPaths = @(
    "C:\Python314",
    "C:\Python313",
    "C:\Python312",
    "C:\Python311",
    "C:\Program Files\Python314",
    "C:\Program Files\Python313",
    "C:\Program Files\Python312",
    "C:\Program Files\Python311",
    "$env:LOCALAPPDATA\Programs\Python\Python314",
    "$env:LOCALAPPDATA\Programs\Python\Python313",
    "$env:LOCALAPPDATA\Programs\Python\Python312",
    "$env:LOCALAPPDATA\Programs\Python\Python311",
    "$env:LOCALAPPDATA\Microsoft\WindowsApps",
    "$env:LOCALAPPDATA\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.14_qbz5n2kfra8p0",
    "$env:LOCALAPPDATA\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0"
)

foreach ($path in $searchPaths) {
    $pythonExe = Join-Path $path "python.exe"
    if (Test-Path $pythonExe) {
        try {
            $version = & $pythonExe --version 2>&1
            if ($LASTEXITCODE -eq 0 -and $version -match "Python (\d+\.\d+\.\d+)") {
                Write-Success "Найден: $pythonExe"
                Write-Host "   Версия: $($Matches[1])" -ForegroundColor Gray
                $pythonPath = $path
                $pythonFound = $true
            }
        } catch {
            # Пропускаем нерабочие установки
        }
    }
}

if ($pythonFound) {
    Write-Host ""
    Write-Host "Python найден, но не добавлен в PATH" -ForegroundColor Yellow
    Write-Host ""

    if ($Quiet) {
        $addToPath = 'Y'
        Write-Success "Тихий режим: автоматическое добавление в PATH"
    } else {
        $addToPath = Read-Host "Добавить найденный Python в PATH? (Y/N)"
    }

    if ($addToPath -eq 'Y' -or $addToPath -eq 'y') {
        Write-Host ""
        Write-Host "Добавление Python в PATH..." -ForegroundColor Cyan

        # Добавление в PATH для текущего пользователя
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $newPath = "$pythonPath;$pythonPath\Scripts;$userPath"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")

        # Обновление PATH для текущей сессии
        $env:Path = "$pythonPath;$pythonPath\Scripts;$env:Path"

        Write-Success "Python добавлен в PATH"
        Write-Host ""
        Write-Host "Проверка доступности..." -ForegroundColor Gray

        try {
            $checkVersion = & python --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Green
                Write-Host "✅ Python настроен и готов к работе!" -ForegroundColor Green
                Write-Host "========================================" -ForegroundColor Green
                Write-Host ""

                if ($env:CALLED_FROM_PARENT -eq "1") {
                    exit 0
                }
                Read-Host "Нажмите Enter для выхода"
                exit 0
            }
        } catch {
            # Продолжаем установку
        }
    }
    Write-Host ""
}

Write-Host "Python не найден в стандартных местах" -ForegroundColor Yellow
Write-Host "Требуется установка Python" -ForegroundColor White
Write-Host ""

# [Шаг 3] Выбор типа установки
Write-Step "[3/9] Выбор типа установки..."
Write-Host ""

$installForAll = $false
$needAdmin = $false

if ($Quiet) {
    # Тихий режим - всегда для текущего пользователя
    $installType = "1"
    Write-Success "Тихий режим: установка для текущего пользователя"
    Write-Host ""
} else {
    # Интерактивный режим
    Write-Host "Выберите тип установки:" -ForegroundColor White
    Write-Host ""
    Write-Host "  [1] Для текущего пользователя (рекомендуется)" -ForegroundColor Green
    Write-Host "      - Не требует прав администратора" -ForegroundColor Gray
    Write-Host "      - Устанавливается в: $env:LOCALAPPDATA\Programs\Python" -ForegroundColor Gray
    Write-Host "      - Доступен только для вашей учетной записи" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] Для всех пользователей" -ForegroundColor Yellow
    Write-Host "      - Требует права администратора" -ForegroundColor Gray
    Write-Host "      - Устанавливается в: C:\Program Files\Python314" -ForegroundColor Gray
    Write-Host "      - Доступен для всех пользователей системы" -ForegroundColor Gray
    Write-Host ""

    $installType = Read-Host "Ваш выбор (1 или 2, Enter = 1)"

    # По умолчанию - для текущего пользователя
    if ([string]::IsNullOrWhiteSpace($installType)) {
        $installType = "1"
    }

    Write-Host ""

    if ($installType -eq "2") {
        $installForAll = $true
        $needAdmin = $true
        Write-Success "Выбрана установка для всех пользователей"
    } else {
        Write-Success "Выбрана установка для текущего пользователя"
    }
    Write-Host ""
}

# [Шаг 4] Проверка прав администратора (если нужно)
if ($needAdmin) {
    Write-Step "[4/9] Проверка прав администратора..."

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Warning "Требуются права администратора"
        Write-Host ""
        Write-Host "Перезапуск с правами администратора..." -ForegroundColor Yellow
        Write-Host ""

        # Перезапуск с правами администратора
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }

    Write-Success "Права администратора получены"
    Write-Host ""
} else {
    Write-Step "[4/9] Права администратора не требуются"
    Write-Success "Установка для текущего пользователя"
    Write-Host ""
}

# [Шаг 5] Определение архитектуры системы
Write-Step "[5/9] Определение архитектуры системы..."

$arch = "x64"
$processorArch = $env:PROCESSOR_ARCHITECTURE

switch ($processorArch) {
    "AMD64" { $arch = "x64" }
    "x86"   { $arch = "x86" }
    "ARM64" { $arch = "arm64" }
}

Write-Success "Архитектура: $arch"
Write-Host ""

# [Шаг 6] Определение версии Python
Write-Step "[6/9] Определение версии Python для установки..."

$pythonVersion = "3.14.0"
$pythonMajor = "3.14"

Write-Success "Будет установлен Python $pythonVersion"
Write-Host ""

# [Шаг 7] Запрос подтверждения у пользователя
Write-Step "[7/9] Подтверждение установки..."
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Параметры установки:" -ForegroundColor White
Write-Host "  • Версия: Python $pythonVersion" -ForegroundColor Gray

if ($installForAll) {
    Write-Host "  • Установка: Для всех пользователей" -ForegroundColor Gray
    Write-Host "  • Путь: C:\Program Files\Python314" -ForegroundColor Gray
} else {
    Write-Host "  • Установка: Для текущего пользователя" -ForegroundColor Gray
    Write-Host "  • Путь: $env:LOCALAPPDATA\Programs\Python\Python314" -ForegroundColor Gray
}

Write-Host "  • PATH: Будет добавлен автоматически" -ForegroundColor Gray
Write-Host "  • Размер: ~30-40 МБ" -ForegroundColor Gray
Write-Host ""

if ($Quiet) {
    Write-Success "Тихий режим: установка без подтверждения"
    Write-Host ""
} else {
    $confirmation = Read-Host "Установить Python? (Y/N)"

    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        Write-Host ""
        Write-Error "Установка отменена пользователем"
        Write-Host ""
        if ($env:CALLED_FROM_PARENT -ne "1") {
            Read-Host "Нажмите Enter для выхода"
        }
        exit 1
    }

    Write-Host ""
    Write-Success "Подтверждение получено"
    Write-Host ""
}

# [Шаг 8] Попытка установки через winget
Write-Step "[8/9] Попытка установки через winget..."

$wingetAvailable = $false
try {
    $null = Get-Command winget -ErrorAction Stop
    $wingetAvailable = $true
} catch {
    $wingetAvailable = $false
}

if ($wingetAvailable) {
    Write-Success "winget обнаружен, начинаем установку..."
    Write-Host ""
    Write-Host "Это может занять несколько минут..." -ForegroundColor Yellow
    Write-Host ""

    try {
        if ($installForAll) {
            # Для всех пользователей
            $result = winget install Python.Python.3.14 --scope machine --silent --accept-package-agreements --accept-source-agreements 2>&1
        } else {
            # Для текущего пользователя
            $result = winget install Python.Python.3.14 --scope user --silent --accept-package-agreements --accept-source-agreements 2>&1
        }

        if ($LASTEXITCODE -eq 0) {
            Write-Host ""
            Write-Success "Python установлен через winget"
            $useWinget = $true
        } else {
            Write-Host ""
            Write-Warning "winget не смог установить Python"
            Write-Host "Переход к альтернативному методу..." -ForegroundColor Yellow
            Write-Host ""
            $useWinget = $false
        }
    } catch {
        Write-Host ""
        Write-Warning "Ошибка при использовании winget: $_"
        Write-Host "Переход к альтернативному методу..." -ForegroundColor Yellow
        Write-Host ""
        $useWinget = $false
    }
} else {
    Write-Warning "winget не найден, используем альтернативный метод"
    Write-Host ""
    $useWinget = $false
}

# Альтернативный метод: скачивание установщика
if (-not $useWinget) {
    Write-Host "Скачивание официального установщика Python..." -ForegroundColor Cyan

    $downloadUrl = ""
    switch ($arch) {
        "x64"   { $downloadUrl = "https://www.python.org/ftp/python/$pythonVersion/python-$pythonVersion-amd64.exe" }
        "x86"   { $downloadUrl = "https://www.python.org/ftp/python/$pythonVersion/python-$pythonVersion.exe" }
        "arm64" { $downloadUrl = "https://www.python.org/ftp/python/$pythonVersion/python-$pythonVersion-arm64.exe" }
    }

    $installerPath = "$env:TEMP\python-installer.exe"

    Write-Host "Скачивание с: $downloadUrl" -ForegroundColor Gray
    Write-Host "Сохранение в: $installerPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Пожалуйста, подождите..." -ForegroundColor Yellow
    Write-Host ""

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -UseBasicParsing
        $ProgressPreference = 'Continue'

        Write-Success "Установщик скачан"
        Write-Host ""
    } catch {
        Write-Host ""
        Write-Error "Ошибка скачивания установщика: $_"
        Write-Host ""
        Write-Host "Попробуйте установить Python вручную:" -ForegroundColor Yellow
        Write-Host "  1. Перейдите на https://www.python.org/downloads/" -ForegroundColor Gray
        Write-Host "  2. Скачайте Python $pythonVersion или новее" -ForegroundColor Gray
        Write-Host "  3. Запустите установщик с опцией `"Add Python to PATH`"" -ForegroundColor Gray
        Write-Host ""
        if ($env:CALLED_FROM_PARENT -ne "1") {
            Read-Host "Нажмите Enter для выхода"
        }
        exit 1
    }

    # Установка Python
    Write-Host "Установка Python $pythonVersion..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Выполняется установка, пожалуйста подождите..." -ForegroundColor Yellow
    Write-Host "Это может занять 2-5 минут..." -ForegroundColor Yellow
    Write-Host ""

    try {
        $installArgs = @(
            "/quiet",
            "PrependPath=1",
            "Include_test=0",
            "Include_launcher=1",
            "SimpleInstall=1"
        )

        if ($installForAll) {
            $installArgs += "InstallAllUsers=1"
        } else {
            $installArgs += "InstallAllUsers=0"
        }

        $process = Start-Process -FilePath $installerPath -ArgumentList $installArgs -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -ne 0) {
            throw "Установщик вернул код ошибки: $($process.ExitCode)"
        }

        Write-Success "Python установлен"
        Write-Host ""
    } catch {
        Write-Host ""
        Write-Error "Ошибка установки Python: $_"
        Write-Host ""
        Write-Host "Выполняется откат..." -ForegroundColor Yellow

        # Попытка удаления частично установленного Python
        try {
            if (Test-Path $installerPath) {
                Start-Process -FilePath $installerPath -ArgumentList @("/uninstall", "/quiet") -Wait -NoNewWindow
            }
        } catch {
            # Игнорируем ошибки отката
        }

        # Удаление установщика
        if (Test-Path $installerPath) {
            Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
        }

        Write-Host ""
        Write-Host "Рекомендуется установить Python вручную:" -ForegroundColor Yellow
        Write-Host "  https://www.python.org/downloads/" -ForegroundColor Gray
        Write-Host ""
        if ($env:CALLED_FROM_PARENT -ne "1") {
            Read-Host "Нажмите Enter для выхода"
        }
        exit 1
    }

    # Очистка
    if (Test-Path $installerPath) {
        Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
    }
}

# [Шаг 9] Проверка установки и настройка PATH
Write-Step "[9/9] Проверка установки и настройка PATH..."
Write-Host ""
Write-Host "Обновление переменных окружения..." -ForegroundColor Gray
Write-Host ""

# Обновление PATH для текущей сессии
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$env:Path = "$machinePath;$userPath"

# Добавим стандартные пути Python явно
$env:Path += ";C:\Python314;C:\Python314\Scripts"
$env:Path += ";C:\Python313;C:\Python313\Scripts"
$env:Path += ";C:\Program Files\Python314;C:\Program Files\Python314\Scripts"
$env:Path += ";C:\Program Files\Python313;C:\Program Files\Python313\Scripts"
$env:Path += ";$env:LOCALAPPDATA\Programs\Python\Python314;$env:LOCALAPPDATA\Programs\Python\Python314\Scripts"
$env:Path += ";$env:LOCALAPPDATA\Programs\Python\Python313;$env:LOCALAPPDATA\Programs\Python\Python313\Scripts"
$env:Path += ";$env:LOCALAPPDATA\Microsoft\WindowsApps"
$env:Path += ";$env:LOCALAPPDATA\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.14_qbz5n2kfra8p0"
$env:Path += ";$env:LOCALAPPDATA\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0"

# Небольшая задержка
Start-Sleep -Seconds 2

# Проверка Python
try {
    $installedVersion = & python --version 2>&1
    if ($LASTEXITCODE -eq 0 -and $installedVersion -match "Python (\d+\.\d+\.\d+)") {
        $versionNumber = $Matches[1]
        Write-Success "Python $versionNumber успешно установлен и доступен"
        Write-Host ""
    } else {
        throw "Python не доступен в PATH"
    }
} catch {
    Write-Warning "Python установлен, но недоступен в PATH"
    Write-Host ""
    Write-Host "Попытка найти Python и настроить PATH..." -ForegroundColor Yellow
    Write-Host ""

    # Расширенный поиск
    $extendedPaths = @(
        "C:\Python314",
        "C:\Python313",
        "C:\Python312",
        "C:\Program Files\Python314",
        "C:\Program Files\Python313",
        "C:\Program Files\Python312",
        "$env:LOCALAPPDATA\Programs\Python\Python314",
        "$env:LOCALAPPDATA\Programs\Python\Python313",
        "$env:LOCALAPPDATA\Programs\Python\Python312",
        "$env:LOCALAPPDATA\Microsoft\WindowsApps",
        "$env:LOCALAPPDATA\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.14_qbz5n2kfra8p0",
        "$env:LOCALAPPDATA\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0"
    )

    $foundPython = $false
    foreach ($path in $extendedPaths) {
        $pythonExe = Join-Path $path "python.exe"
        if (Test-Path $pythonExe) {
            try {
                $version = & $pythonExe --version 2>&1
                if ($LASTEXITCODE -eq 0 -and $version -match "Python (\d+\.\d+\.\d+)") {
                    Write-Success "Найден: $pythonExe"
                    $env:Path = "$path;$path\Scripts;$env:Path"

                    $checkVersion = & python --version 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Success "Python $($Matches[1]) успешно настроен для текущей сессии"
                        $foundPython = $true
                        $versionNumber = $Matches[1]
                        break
                    }
                }
            } catch {
                # Продолжаем поиск
            }
        }
    }

    if (-not $foundPython) {
        Write-Host ""
        Write-Warning "Python установлен, но требуется перезапуск терминала"
        Write-Host ""
        Write-Host "Пожалуйста:" -ForegroundColor Yellow
        Write-Host "  1. Закройте это окно PowerShell" -ForegroundColor Gray
        Write-Host "  2. Откройте новое окно PowerShell" -ForegroundColor Gray
        Write-Host "  3. Python будет доступен автоматически" -ForegroundColor Gray
        Write-Host ""
        if ($env:CALLED_FROM_PARENT -ne "1") {
            Read-Host "Нажмите Enter для выхода"
        }
        exit 0
    }
}

# Проверка pip
try {
    $null = & python -m pip --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "pip доступен"
    } else {
        throw "pip не найден"
    }
} catch {
    Write-Warning "pip не найден, выполняется установка..."
    try {
        & python -m ensurepip --upgrade 2>&1 | Out-Null
        Write-Success "pip установлен"
    } catch {
        # Пропускаем ошибку
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "✅ Python готов к работе!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

# Если скрипт запущен из другого скрипта, вернуться туда
if ($env:CALLED_FROM_PARENT -eq "1") {
    exit 0
}

Read-Host "Нажмите Enter для выхода"

exit 0
