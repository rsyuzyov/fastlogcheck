#!/bin/bash
# Скрипт установки зависимостей для Server Logs Analysis Tool

echo "================================"
echo "Server Logs Analysis Tool"
echo "Установка зависимостей"
echo "================================"
echo ""

# Проверка Python версии
echo "[1/4] Проверка версии Python..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]); then
    echo "❌ Требуется Python 3.9+, установлено: $PYTHON_VERSION"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION"
echo ""

# Проверка pip
echo "[2/4] Проверка pip3..."
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 не найден. Установите: apt install python3-pip"
    exit 1
fi

echo "✅ pip3 установлен"
echo ""

# Установка зависимостей
echo "[3/4] Установка зависимостей..."
pip3 install -q paramiko jinja2

if [ $? -eq 0 ]; then
    echo "✅ Зависимости установлены"
else
    echo "❌ Ошибка установки зависимостей"
    exit 1
fi
echo ""

# Проверка установки
echo "[4/4] Проверка установки..."
python3 -c "import paramiko, jinja2" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "✅ Все модули импортируются корректно"
else
    echo "❌ Ошибка импорта модулей"
    exit 1
fi
echo ""

# Создание директории для отчётов (опционально)
if [ ! -d "reports" ]; then
    mkdir -p reports
    echo "✅ Создана директория ./reports/"
fi

echo "================================"
echo "✅ Установка завершена успешно!"
echo "================================"
echo ""
echo "Примеры использования:"
echo ""
echo "  # Базовая проверка"
echo "  ./check_server_logs.py srv-hv4"
echo ""
echo "  # С автоочисткой ZFS"
echo "  ./check_server_logs.py srv-hv4 --cleanup-threshold 85"
echo ""
echo "  # Несколько серверов"
echo "  ./check_server_logs.py srv-hv1 srv-hv2 srv-hv4"
echo ""
echo "Подробнее: см. README.md"
echo ""
