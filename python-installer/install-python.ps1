# Универсальный скрипт автоматической установки Python для Windows
# Версия: 1.0.0
# Поддерживаемые системы: Windows 10+, Windows Server 2019+
# Архитектуры: x86, x64, ARM64

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

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
Write-Host "Автоматическая установка Python" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# [1/7] Проверка прав администратора
Write-Step "[1/7] Проверка прав администратора..."

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

# [2/7] Определение архитектуры системы
Write-Step "[2/7] Определение архитектуры системы..."

$arch = "x64"
$processorArch = $env:PROCESSOR_ARCHITECTURE

switch ($processorArch) {
    "AMD64" { $arch = "x64" }
    "x86"   { $arch = "x86" }
    "ARM64" { $arch = "arm64" }
}

Write-Success "Архитектура: $arch"
Write-Host ""

# [3/7] Определение версии Python
Write-Step "[3/7] Определение версии Python для установки..."

$pythonVersion = "3.13.1"
$pythonMajor = "3.13"

Write-Success "Будет установлен Python $pythonVersion"
Write-Host ""

# Запрос подтверждения у пользователя
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Python не найден в системе." -ForegroundColor Yellow
Write-Host ""
Write-Host "Предлагается установить Python $pythonVersion ($arch)" -ForegroundColor White
Write-Host ""
Write-Host "Параметры установки:" -ForegroundColor White
Write-Host "  • Версия: Python $pythonVersion" -ForegroundColor Gray
Write-Host "  • Установка: Для всех пользователей" -ForegroundColor Gray
Write-Host "  • PATH: Будет добавлен автоматически" -ForegroundColor Gray
Write-Host "  • Размер: ~30-40 МБ" -ForegroundColor Gray
Write-Host ""

$confirmation = Read-Host "Установить Python? (Y/N)"

if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
    Write-Host ""
    Write-Error "Установка отменена пользователем"
    Write-Host ""
    Read-Host "Нажмите Enter для выхода"
    exit 1
}

Write-Host ""
Write-Success "Подтверждение получено"
Write-Host ""

# [4/7] Попытка установки через winget
Write-Step "[4/7] Попытка установки через winget..."

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
        $wingetResult = winget install Python.Python.3.13 --silent --accept-package-agreements --accept-source-agreements 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host ""
            Write-Success "Python установлен через winget"
            $useWinget = $true
            # Переход к проверке установки
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
    Write-Step "[5/7] Скачивание официального установщика Python..."

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

        # Скачивание с прогресс-баром
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
        Read-Host "Нажмите Enter для выхода"
        exit 1
    }

    # [6/7] Установка Python
    Write-Step "[6/7] Установка Python $pythonVersion..."
    Write-Host ""
    Write-Host "Выполняется установка, пожалуйста подождите..." -ForegroundColor Yellow
    Write-Host "Это может занять 2-5 минут..." -ForegroundColor Yellow
    Write-Host ""

    try {
        $installArgs = @(
            "/quiet",
            "InstallAllUsers=1",
            "PrependPath=1",
            "Include_test=0",
            "Include_launcher=1",
            "SimpleInstall=1"
        )

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
        Read-Host "Нажмите Enter для выхода"
        exit 1
    }

    # Очистка
    if (Test-Path $installerPath) {
        Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
    }
}

# [7/7] Проверка установки
Write-Step "[7/7] Проверка установки..."
Write-Host ""
Write-Host "Обновление переменных окружения..." -ForegroundColor Gray
Write-Host ""

# Обновление PATH для текущей сессии
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$env:Path = "$machinePath;$userPath"

# Небольшая задержка для завершения установки
Start-Sleep -Seconds 2

# Проверка Python
try {
    $pythonCmd = Get-Command python -ErrorAction Stop
    $installedVersion = & python --version 2>&1

    if ($installedVersion -match "Python (\d+\.\d+\.\d+)") {
        $versionNumber = $Matches[1]
        Write-Success "Python $versionNumber успешно установлен и доступен"
        Write-Host ""
    } else {
        throw "Не удалось определить версию Python"
    }
} catch {
    Write-Warning "Python установлен, но требуется перезапуск"
    Write-Host ""
    Write-Host "Пожалуйста:" -ForegroundColor Yellow
    Write-Host "  1. Закройте это окно PowerShell" -ForegroundColor Gray
    Write-Host "  2. Откройте новое окно PowerShell" -ForegroundColor Gray
    Write-Host "  3. Проверьте установку: python --version" -ForegroundColor Gray
    Write-Host ""
    Read-Host "Нажмите Enter для выхода"
    exit 0
}

# Проверка pip
try {
    $null = & python -m pip --version 2>&1
    Write-Success "pip доступен"
} catch {
    Write-Warning "pip не найден, выполняется установка..."
    try {
        & python -m ensurepip --upgrade 2>&1 | Out-Null
        Write-Success "pip установлен"
    } catch {
        Write-Warning "Не удалось установить pip автоматически"
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "✅ Установка Python завершена успешно!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Python $versionNumber установлен и готов к использованию" -ForegroundColor White
Write-Host ""

# Если скрипт запущен из другого скрипта, вернуться туда
if ($env:CALLED_FROM_PARENT -eq "1") {
    exit 0
}

Read-Host "Нажмите Enter для выхода"

exit 0
