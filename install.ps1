# Скрипт установки зависимостей для Server Logs Analysis Tool
# PowerShell version for Windows

# Установка кодировки UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Server Logs Analysis Tool" -ForegroundColor Cyan
Write-Host "Установка зависимостей" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Проверка Python версии
Write-Host "[1/4] Проверка версии Python..." -ForegroundColor Yellow

try {
    $pythonVersion = & python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python не найден"
    }

    $versionMatch = $pythonVersion -match 'Python (\d+)\.(\d+)\.(\d+)'
    if ($versionMatch) {
        $major = [int]$matches[1]
        $minor = [int]$matches[2]
        $patch = [int]$matches[3]

        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 9)) {
            Write-Host "❌ Требуется Python 3.9+, установлено: Python $major.$minor.$patch" -ForegroundColor Red
            Write-Host ""
            Write-Host "Установите Python 3.9 или новее:" -ForegroundColor Yellow
            Write-Host "  1. Перейдите на https://www.python.org/downloads/" -ForegroundColor White
            Write-Host "  2. Скачайте установщик Python 3.12 или новее" -ForegroundColor White
            Write-Host "  3. При установке ОБЯЗАТЕЛЬНО отметьте:" -ForegroundColor White
            Write-Host "     ✓ Add Python to PATH" -ForegroundColor Green
            Write-Host "  4. После установки перезапустите PowerShell" -ForegroundColor White
            Write-Host ""
            pause
            exit 1
        }

        Write-Host "✅ Python $major.$minor.$patch" -ForegroundColor Green
    }
    else {
        throw "Не удалось определить версию Python"
    }
}
catch {
    Write-Host "❌ Python не найден или не добавлен в PATH" -ForegroundColor Red
    Write-Host ""
    Write-Host "Для установки Python:" -ForegroundColor Yellow
    Write-Host "  1. Перейдите на https://www.python.org/downloads/" -ForegroundColor White
    Write-Host "  2. Скачайте установщик Python 3.12 или новее" -ForegroundColor White
    Write-Host "  3. Запустите установщик и ОБЯЗАТЕЛЬНО отметьте:" -ForegroundColor White
    Write-Host "     ✓ Add Python to PATH" -ForegroundColor Green
    Write-Host "  4. После установки перезапустите PowerShell и запустите скрипт снова" -ForegroundColor White
    Write-Host ""
    Write-Host "Альтернатива - установка через winget:" -ForegroundColor Yellow
    Write-Host "  winget install Python.Python.3.12" -ForegroundColor White
    Write-Host ""
    pause
    exit 1
}

Write-Host ""

# Проверка pip
Write-Host "[2/4] Проверка pip..." -ForegroundColor Yellow

try {
    & python -m pip --version 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "pip не найден"
    }
    Write-Host "✅ pip установлен" -ForegroundColor Green
}
catch {
    Write-Host "❌ pip не найден" -ForegroundColor Red
    Write-Host ""
    Write-Host "Установите pip:" -ForegroundColor Yellow
    Write-Host "  python -m ensurepip --upgrade" -ForegroundColor White
    Write-Host ""
    pause
    exit 1
}

Write-Host ""

# Установка зависимостей
Write-Host "[3/4] Установка зависимостей..." -ForegroundColor Yellow

try {
    & python -m pip install -q paramiko jinja2
    if ($LASTEXITCODE -ne 0) {
        throw "Ошибка установки"
    }
    Write-Host "✅ Зависимости установлены (paramiko, jinja2)" -ForegroundColor Green
}
catch {
    Write-Host "❌ Ошибка установки зависимостей" -ForegroundColor Red
    Write-Host ""
    Write-Host "Попробуйте установить вручную:" -ForegroundColor Yellow
    Write-Host "  python -m pip install paramiko jinja2" -ForegroundColor White
    Write-Host ""
    pause
    exit 1
}

Write-Host ""

# Проверка установки
Write-Host "[4/4] Проверка установки..." -ForegroundColor Yellow

try {
    & python -c "import paramiko, jinja2" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Ошибка импорта"
    }
    Write-Host "✅ Все модули импортируются корректно" -ForegroundColor Green
}
catch {
    Write-Host "❌ Ошибка импорта модулей" -ForegroundColor Red
    Write-Host ""
    Write-Host "Попробуйте переустановить модули:" -ForegroundColor Yellow
    Write-Host "  python -m pip install --upgrade --force-reinstall paramiko jinja2" -ForegroundColor White
    Write-Host ""
    pause
    exit 1
}

Write-Host ""

# Создание директории для отчётов (опционально)
if (-not (Test-Path "reports")) {
    New-Item -ItemType Directory -Path "reports" -Force | Out-Null
    Write-Host "✅ Создана директория .\reports\" -ForegroundColor Green
}

Write-Host "================================" -ForegroundColor Cyan
Write-Host "✅ Установка завершена успешно!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Примеры использования:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  # Базовая проверка" -ForegroundColor Gray
Write-Host "  python check_server_logs.py srv-hv1.ag.local" -ForegroundColor White
Write-Host ""
Write-Host "  # Несколько серверов" -ForegroundColor Gray
Write-Host "  python check_server_logs.py srv-hv1.ag.local srv-hv2.ag.local" -ForegroundColor White
Write-Host ""
Write-Host "Подробнее: см. README.md и USAGE.md" -ForegroundColor Yellow
Write-Host ""
pause
