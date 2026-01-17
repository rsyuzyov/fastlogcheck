#!/usr/bin/env python3
"""
Server Logs Analysis Tool
Подключается к серверам по SSH и анализирует логи за указанный период
"""

import argparse
import getpass
import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import paramiko
from jinja2 import Environment, FileSystemLoader, select_autoescape


def get_executable_dir() -> Path:
    """Получить директорию исполняемого файла"""
    if getattr(sys, 'frozen', False):
        # Запущен через PyInstaller - берём директорию exe-файла
        return Path(sys.executable).parent
    else:
        # Обычный запуск - директория скрипта
        return Path(__file__).parent


def get_resource_path(relative_path: str, prefer_local: bool = False) -> Path:
    """Получить путь к ресурсу (работает как для dev, так и для PyInstaller)
    
    Args:
        relative_path: относительный путь к ресурсу
        prefer_local: если True, сначала ищет файл рядом с exe/скриптом
    """
    # Для PyInstaller - сначала проверяем рядом с exe-файлом
    if prefer_local or getattr(sys, 'frozen', False):
        local_path = get_executable_dir() / relative_path
        if local_path.exists():
            return local_path
    
    if getattr(sys, 'frozen', False):
        # Запущен через PyInstaller - используем встроенные ресурсы
        base_path = Path(sys._MEIPASS)
    else:
        # Обычный запуск
        base_path = Path(__file__).parent
    return base_path / relative_path


def cleanup_old_logs(logs_dir: Path):
    """Удаление логов старше 1 месяца"""
    cutoff = datetime.now() - timedelta(days=30)

    try:
        for log_file in logs_dir.glob("*.log"):
            try:
                if log_file.stat().st_mtime < cutoff.timestamp():
                    log_file.unlink()
            except Exception:
                pass  # Игнорируем ошибки удаления
    except Exception:
        pass


# Настройка логирования
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Настройка логирования"""
    level = logging.DEBUG if verbose else logging.INFO

    # Создаем директорию для логов
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    # Очищаем старые логи
    cleanup_old_logs(logs_dir)

    # Формируем имя файла с текущей датой и временем
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = logs_dir / f"{timestamp}.log"

    # Логирование в консоль с поддержкой UTF-8
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_formatter)
    # Принудительно устанавливаем UTF-8 для консоли
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    # Логирование в файл с UTF-8
    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)

    # Настройка root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    # Отключаем verbose логи paramiko
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    return logger


# Парсинг аргументов командной строки
def parse_arguments() -> argparse.Namespace:
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description="Анализ логов серверов через SSH",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    Примеры использования:
      %(prog)s server1.example.com
      %(prog)s admin@192.168.1.100 --ask-password
      %(prog)s server1.example.com server2.example.com server3.example.com --period 48
      %(prog)s --file servers.txt --period 48
      %(prog)s server1.example.com --cleanup-threshold 85 --verbose
      %(prog)s server1.example.com --output ./my_reports
            """,
    )

    parser.add_argument(
        "hostnames", nargs="*", help="Один или несколько хостов для проверки (поддерживается формат user@host)"
    )

    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Файл со списком серверов (по одному на строку)",
    )

    parser.add_argument(
        "--use-ssh-config",
        action="store_true",
        help="Использовать список хостов из SSH конфига",
    )

    parser.add_argument(
        "--period",
        type=int,
        default=24,
        help="Период анализа в часах (по умолчанию: 24)",
    )

    parser.add_argument(
        "--output",
        type=str,
        default="reports",
        help="Каталог для отчётов (по умолчанию: reports). Файлы: report_HOSTNAME_YYYY-MM-DD_HH-MM.html",
    )

    parser.add_argument(
        "--cleanup-threshold",
        type=int,
        default=None,
        help="Автоочистка ZFS при превышении N%% (по умолчанию: выключено)",
    )

    parser.add_argument(
        "--parallel",
        type=int,
        default=4,
        help="Количество параллельных потоков (по умолчанию: 4)",
    )

    parser.add_argument(
        "--ssh-config",
        type=str,
        default=None,
        help="Путь к SSH конфигу (по умолчанию: системные настройки SSH)",
    )

    parser.add_argument(
        "--ssh-user",
        type=str,
        default="root",
        help="Пользователь SSH (по умолчанию: root)",
    )

    parser.add_argument(
        "--ssh-timeout",
        type=int,
        default=30,
        help="Timeout SSH команд в секундах (по умолчанию: 30)",
    )

    parser.add_argument(
        "--ask-password",
        action="store_true",
        help="Запросить пароль для SSH подключения (безопасный ввод)",
    )

    parser.add_argument(
        "--verbose", action="store_true", help="Подробный вывод в консоль"
    )

    parser.add_argument(
        "--json", action="store_true", help="Дополнительно сохранить результаты в JSON"
    )

    # AI-friendly вывод
    parser.add_argument(
        "--ai-output",
        action="store_true",
        help="Вывод в AI-friendly JSON формате (stdout, без HTML)"
    )

    parser.add_argument(
        "--ai-verbose",
        action="store_true",
        help="Включить полные данные (все записи логов) в AI-вывод"
    )

    parser.add_argument(
        "--ai-format",
        type=str,
        choices=["compact", "standard", "full"],
        default="standard",
        help="Формат AI-вывода: compact (минимум), standard (по умолчанию), full (все детали)"
    )

    parser.add_argument(
        "--min-severity",
        type=str,
        choices=["critical", "warning", "info"],
        default="warning",
        help="Минимальный уровень severity для включения в отчёт (по умолчанию: warning)"
    )

    return parser.parse_args()


def read_servers_from_file(filepath: str) -> List[str]:
    """Чтение списка серверов из файла"""
    servers = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                # Удаляем пробелы и переводы строк
                line = line.strip()
                # Игнорируем пустые строки и комментарии
                if line and not line.startswith("#"):
                    servers.append(line)
        return servers
    except FileNotFoundError:
        raise FileNotFoundError(f"Файл не найден: {filepath}")
    except Exception as e:
        raise Exception(f"Ошибка при чтении файла {filepath}: {e}")


def parse_host_string(host_string: str) -> Tuple[str, Optional[str]]:
    """Парсинг строки хоста в формате [user@]hostname
    
    Поддерживаемые форматы:
    - hostname                    -> (hostname, None)
    - user@hostname               -> (hostname, user)
    - admin@192.168.1.100         -> (192.168.1.100, admin)
    
    Returns:
        Tuple[str, Optional[str]]: (hostname, username или None)
    """
    if '@' in host_string:
        parts = host_string.split('@', 1)
        username = parts[0]
        hostname = parts[1]
        return hostname, username
    return host_string, None


def read_hosts_from_ssh_config(ssh_config_path: Optional[str] = None) -> List[str]:
    """Чтение списка хостов из SSH конфига"""
    hosts = []

    try:
        # Определяем путь к SSH конфигу
        if ssh_config_path is None:
            config_path = Path.home() / ".ssh" / "config"
        else:
            config_path = Path(ssh_config_path).expanduser()

        if not config_path.exists():
            raise FileNotFoundError(f"SSH конфиг не найден: {config_path}")

        # Парсим SSH конфиг
        ssh_config = paramiko.SSHConfig()
        with open(config_path, "r", encoding="utf-8") as f:
            ssh_config.parse(f)

        # Извлекаем все хосты из конфига
        # В paramiko SSHConfig хосты хранятся в _config
        if hasattr(ssh_config, "_config"):
            for host_config in ssh_config._config:
                if "host" in host_config:
                    host_patterns = host_config["host"]
                    for pattern in host_patterns:
                        # Игнорируем wildcards и специальные паттерны
                        if "*" not in pattern and "?" not in pattern and pattern != "":
                            hosts.append(pattern)

        return hosts

    except FileNotFoundError:
        raise
    except Exception as e:
        raise Exception(f"Ошибка при чтении SSH конфига: {e}")


# Дата-классы для хранения результатов
@dataclass
class ReportFileInfo:
    """Информация о файле отчёта"""
    filepath: Path
    hostname: str
    timestamp: datetime
    date_str: str  # YYYY-MM-DD для группировки
    time_str: str  # HH:MM для отображения
    domain_group: str


@dataclass
class ReportMetadata:
    """Метаданные отчёта (извлечённые из HTML)"""
    hostname: str
    timestamp: str
    total_errors: int
    total_warnings: int
    status: str  # 'error', 'warning', 'success', 'connection_error'
    period_hours: int = 24


@dataclass
class LogEntry:
    """Запись лога"""

    timestamp: str
    type: str
    severity: str  # 'critical', 'warning', 'info'
    message: str
    source: str = ""


@dataclass
class CheckResult:
    """Результат одной проверки"""

    name: str
    source_name: str
    source_path: str
    errors: int
    warnings: int
    status: str  # 'success', 'warning', 'error', 'connection_error'
    entries: List[LogEntry] = field(default_factory=list)
    details: Dict = field(default_factory=dict)


@dataclass
class ServerReport:
    """Отчёт по серверу"""

    hostname: str
    timestamp: str
    period_hours: int
    connection_error: Optional[str]
    checks: List[CheckResult]
    total_errors: int = 0
    total_warnings: int = 0
    uptime: str = ""
    load_average: str = ""


class SSHConnection:
    """Управление SSH соединением"""

    def __init__(
        self,
        hostname: str,
        username: str = "root",
        ssh_config: Optional[str] = None,
        timeout: int = 30,
        password: Optional[str] = None,
    ):
        self.hostname = hostname
        self.username = username
        # Если конфиг не указан, пытаемся использовать стандартный
        if ssh_config is None:
            default_config = Path.home() / ".ssh" / "config"
            if default_config.exists():
                ssh_config = str(default_config)
        self.ssh_config = ssh_config
        self.timeout = timeout
        self.password = password
        self.client = None
        self.logger = logging.getLogger(f"SSH[{hostname}]")

    def connect(self) -> Tuple[bool, Optional[str]]:
        """Подключение к серверу"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": self.hostname,
                "username": self.username,
                "timeout": self.timeout,
            }

            # Если указан пароль - используем аутентификацию по паролю
            if self.password:
                connect_kwargs["password"] = self.password
                connect_kwargs["look_for_keys"] = False
                connect_kwargs["allow_agent"] = False
            else:
                # Иначе используем аутентификацию по ключу
                connect_kwargs["look_for_keys"] = True
                connect_kwargs["allow_agent"] = True

            # Если указан SSH config, используем его
            if self.ssh_config:
                ssh_config_path = Path(self.ssh_config).expanduser()
                if ssh_config_path.exists():
                    ssh_config_obj = paramiko.SSHConfig()
                    with open(ssh_config_path) as f:
                        ssh_config_obj.parse(f)

                    host_config = ssh_config_obj.lookup(self.hostname)

                    # Применяем настройки из конфига
                    if "hostname" in host_config:
                        connect_kwargs["hostname"] = host_config["hostname"]
                    if "user" in host_config:
                        connect_kwargs["username"] = host_config["user"]
                    if "port" in host_config:
                        connect_kwargs["port"] = int(host_config["port"])
                    # Если используем пароль, не применяем ключи из конфига
                    if "identityfile" in host_config and not self.password:
                        connect_kwargs["key_filename"] = host_config["identityfile"]

            self.client.connect(**connect_kwargs)
            self.logger.info("✓ Подключение установлено")
            return True, None

        except paramiko.AuthenticationException as e:
            error_msg = f"Ошибка аутентификации: {str(e)}"
            self.logger.error(f"✗ {error_msg}")
            return False, error_msg
        except paramiko.SSHException as e:
            error_msg = f"Ошибка SSH: {str(e)}"
            self.logger.error(f"✗ {error_msg}")
            return False, error_msg
        except Exception as e:
            error_msg = f"Ошибка подключения: {str(e)}"
            self.logger.error(f"✗ {error_msg}")
            return False, error_msg

    def execute(self, command: str, retries: int = 3) -> Tuple[str, str, int]:
        """Выполнение команды с retry"""
        for attempt in range(retries):
            try:
                stdin, stdout, stderr = self.client.exec_command(
                    command, timeout=self.timeout
                )
                stdout_text = stdout.read().decode("utf-8", errors="replace")
                stderr_text = stderr.read().decode("utf-8", errors="replace")
                exit_code = stdout.channel.recv_exit_status()

                return stdout_text, stderr_text, exit_code

            except Exception as e:
                if attempt < retries - 1:
                    self.logger.warning(
                        f"Попытка {attempt + 1}/{retries} не удалась: {e}"
                    )
                    continue
                else:
                    self.logger.error(
                        f"Команда не выполнена после {retries} попыток: {e}"
                    )
                    return "", str(e), -1

        return "", "Max retries exceeded", -1

    def close(self):
        """Закрытие соединения"""
        if self.client:
            self.client.close()
            self.logger.info("Соединение закрыто")


def classify_severity(message: str, check_name: str) -> str:
    """Классификация критичности сообщения"""
    message_lower = message.lower()

    # Критические ошибки
    critical_patterns = [
        "degraded",
        "unavail",
        "failed",
        "critical",
        "panic",
        "out of memory",
        "disk full",
        "no space left",
        "cannot allocate",
        "segfault",
        "kernel panic",
    ]

    # Некритические предупреждения
    warning_patterns = [
        "inotify",
        "warning",
        "deprecated",
        "retry",
        "timeout",
        "slow",
        "high load",
    ]

    # Проверяем на критичность
    for pattern in critical_patterns:
        if pattern in message_lower:
            return "critical"

    # Проверяем на предупреждения
    for pattern in warning_patterns:
        if pattern in message_lower:
            return "warning"

    # Специальные правила для конкретных проверок
    if check_name == "journalctl_errors":
        # termproxy единичные ошибки - не критичны
        if "termproxy" in message_lower and "failed: exit code 1" in message_lower:
            return "warning"

    return "critical"


# Глобальная переменная для правил группировки
CUSTOM_GROUPING_RULES = {}

# Паттерны для категоризации проблем (для AI-вывода)
CATEGORY_PATTERNS = {
    "storage": [
        r"disk.*full",
        r"no space left",
        r"zfs.*degraded",
        r"cannot allocate",
        r"Раздел.*%.*использовано",
        r"df\s",
        r"mount.*failed",
        r"filesystem.*full",
        r"quota.*exceeded"
    ],
    "cluster": [
        r"quorum",
        r"corosync",
        r"pvecm",
        r"node.*offline",
        r"cluster.*failed",
        r"cman",
        r"pacemaker",
        r"no active links",
        r"link.*down"
    ],
    "kernel": [
        r"kernel",
        r"\boom\b",
        r"out of memory",
        r"segfault",
        r"panic",
        r"dmesg",
        r"oom.killer",
        r"page allocation failure",
        r"call trace"
    ],
    "authentication": [
        r"auth",
        r"login.*fail",
        r"invalid.*password",
        r"fail2ban",
        r"banned",
        r"sshd.*failed",
        r"authentication failure",
        r"pam_unix",
        r"sudo.*incorrect",
        r"su\[.*failed"
    ],
    "services": [
        r"systemd",
        r"service.*failed",
        r"unit.*failed",
        r"timeout",
        r"\.service.*failed",
        r"job.*failed",
        r"restart.*failed"
    ],
    "network": [
        r"link.*down",
        r"connection.*refused",
        r"network.*unreachable",
        r"no route",
        r"socket.*timeout",
        r"dns.*failed",
        r"interface.*down"
    ],
    "virtualization": [
        r"qm\s",
        r"vm\s+\d+",
        r"pct\s",
        r"container",
        r"migration.*failed",
        r"kvm",
        r"qemu",
        r"lxc",
        r"находится в состоянии STOPPED"
    ],
    "replication": [
        r"replication",
        r"replicate",
        r"sync.*failed",
        r"rsync.*error"
    ]
}


# Dataclasses для AI-friendly вывода
@dataclass
class AIIssueSummary:
    """Краткое описание проблемы для AI"""
    server: str
    category: str
    message: str
    severity: str
    count: int = 1


@dataclass
class AICategorySummary:
    """Сводка по категории проблем"""
    total_count: int
    max_severity: str
    affected_servers: List[str]
    examples: List[str]


@dataclass
class AIServerSummary:
    """Сводка по серверу для AI"""
    status: str  # critical, warning, ok, unreachable
    connection_error: Optional[str]
    hostname: str
    uptime: str
    load_average: str
    errors: int
    warnings: int
    categories_affected: List[str]
    top_issues: List[Dict]


@dataclass
class AIOutput:
    """AI-friendly структура вывода"""
    format_version: str
    format_type: str
    generated_at: str
    check_params: Dict
    summary: Dict
    critical_issues: List[Dict]
    issues_by_category: Dict[str, Dict]
    servers: Dict[str, Dict]
    detailed_logs: Optional[Dict] = None


def load_grouping_rules():
    """Загрузка правил группировки из JSON файла
    
    Порядок поиска файла:
    1. Рядом с исполняемым файлом (exe) или скриптом
    2. Встроенный в PyInstaller бандл (если запущен через PyInstaller)
    
    Если файл не найден рядом с exe, но есть встроенный - копирует его рядом с exe.
    """
    global CUSTOM_GROUPING_RULES

    local_rules_file = get_executable_dir() / "grouping_rules.json"
    
    # Если файла нет рядом с exe - создаём его из встроенного
    if not local_rules_file.exists():
        try:
            # Получаем путь к встроенному файлу
            if getattr(sys, 'frozen', False):
                bundled_path = Path(sys._MEIPASS) / "grouping_rules.json"
            else:
                bundled_path = Path(__file__).parent / "grouping_rules.json"
            
            if bundled_path.exists():
                # Копируем встроенный файл рядом с exe
                import shutil
                shutil.copy2(bundled_path, local_rules_file)
                logging.info(f"Создан файл правил группировки: {local_rules_file}")
        except Exception as e:
            logging.warning(f"Не удалось создать локальный файл правил: {e}")

    # prefer_local=True - сначала ищем рядом с exe/скриптом
    rules_file = get_resource_path("grouping_rules.json", prefer_local=True)

    try:
        with open(rules_file, "r", encoding="utf-8") as f:
            CUSTOM_GROUPING_RULES = json.load(f)
        logging.info(f"Загружены правила группировки из {rules_file}")
    except Exception as e:
        logging.error(f"Ошибка загрузки правил группировки: {e}")
        CUSTOM_GROUPING_RULES = {}


def normalize_message(text: str) -> str:
    """Нормализация сообщения для группировки"""
    # IP v4
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "{IP}", text)
    # Hex numbers (0x...)
    text = re.sub(r"0x[0-9a-fA-F]+", "{HEX}", text)
    # PIDs in brackets [123]
    text = re.sub(r"\[\d+\]", "[{PID}]", text)
    # Numbers (исключая те, что уже заменены)
    text = re.sub(r"\b\d+\b", "{N}", text)
    # Удаляем временные метки в начале строки (если они есть)
    text = re.sub(r"^\w+\s+\d+\s+\d+:\d+:\d+\s+", "", text)
    return text.strip()


@dataclass
class GroupedLogEntry:
    """Сгруппированная запись лога"""

    count: int
    first_timestamp: str
    last_timestamp: str
    entry: LogEntry
    group_message: str
    custom_severity: Optional[str]  # Переопределенная критичность из правил
    all_entries: List[LogEntry] = field(default_factory=list)


def group_entries(entries: List[LogEntry]) -> List[GroupedLogEntry]:
    """Группировка похожих записей"""
    if not entries:
        return []

    groups = {}
    result = []

    # Сохраняем порядок появления групп
    group_order = []

    for entry in entries:
        # Проверяем кастомные правила группировки
        custom_msg = None
        custom_severity = None
        skip_entry = False
        matched_rule = False

        for pattern, rule_config in CUSTOM_GROUPING_RULES.items():
            # Используем regex для проверки
            try:
                if re.search(pattern, entry.message):
                    matched_rule = True
                    # Новый формат: {"title": "...", "severity": "..."}
                    if isinstance(rule_config, dict):
                        custom_msg = f"{rule_config.get('title', pattern)}"
                        severity_value = rule_config.get("severity", "")

                        if severity_value == "skip":
                            skip_entry = True
                            break
                        elif severity_value:  # Не пустая строка
                            custom_severity = severity_value
                    break
            except re.error as e:
                logging.warning(
                    f"Некорректное регулярное выражение в правиле '{pattern}': {e}"
                )
                continue

        # Пропускаем события с severity="skip"
        if skip_entry:
            continue

        if custom_msg:
            norm_msg = custom_msg
        else:
            # Автоматическая группировка для всех остальных событий
            norm_msg = normalize_message(entry.message)

        # Ключ группировки
        key = (entry.type, entry.severity, norm_msg)

        if key not in groups:
            groups[key] = {
                "count": 0,
                "first_timestamp": entry.timestamp,
                "last_timestamp": entry.timestamp,
                "entry": entry,
                "group_message": norm_msg,
                "custom_severity": custom_severity,
                "all_entries": [],
            }
            group_order.append(key)

        groups[key]["count"] += 1
        groups[key]["last_timestamp"] = entry.timestamp
        groups[key]["all_entries"].append(entry)

    # Формируем результат
    for key in group_order:
        data = groups[key]
        result.append(
            GroupedLogEntry(
                count=data["count"],
                first_timestamp=data["first_timestamp"],
                last_timestamp=data["last_timestamp"],
                entry=data["entry"],
                group_message=data["group_message"],
                custom_severity=data["custom_severity"],
                all_entries=data["all_entries"],
            )
        )

    return result


# Функции проверок
class ServerChecks:
    """Класс с методами проверок сервера"""

    def __init__(self, ssh: SSHConnection, period_hours: int):
        self.ssh = ssh
        self.period_hours = period_hours
        self.logger = logging.getLogger(f"Checks[{ssh.hostname}]")

    def check_journalctl_errors(self) -> CheckResult:
        """Проверка системного журнала (ошибки)"""
        result = CheckResult(
            name="journalctl_errors",
            source_name="Системный журнал (критические)",
            source_path="journalctl --priority=err",
            errors=0,
            warnings=0,
            status="success",
        )

        try:
            cmd = f'journalctl --since "{self.period_hours} hours ago" --priority=err --no-pager'
            stdout, stderr, code = self.ssh.execute(cmd)

            if code != 0:
                result.status = "error"
                return result

            lines = [l for l in stdout.strip().split("\n") if l]

            for line in lines:
                # Парсим строку journalctl
                match = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(.+)", line)
                if match:
                    timestamp, message = match.groups()
                    severity = classify_severity(message, "journalctl_errors")

                    entry = LogEntry(
                        timestamp=timestamp,
                        type="Error",
                        severity=severity,
                        message=message,
                    )
                    result.entries.append(entry)

                    if severity == "critical":
                        result.errors += 1
                    else:
                        result.warnings += 1

            if result.errors > 0:
                result.status = "error"
            elif result.warnings > 0:
                result.status = "warning"

        except Exception as e:
            self.logger.error(f"check_journalctl_errors: {e}")
            result.status = "error"

        return result

    def check_journalctl_warnings(self) -> CheckResult:
        """Проверка системного журнала (предупреждения)"""
        result = CheckResult(
            name="journalctl_warnings",
            source_name="Системный журнал (предупреждения)",
            source_path="journalctl --priority=warning",
            errors=0,
            warnings=0,
            status="success",
        )

        try:
            cmd = f'journalctl --since "{self.period_hours} hours ago" --priority=warning --no-pager'
            stdout, stderr, code = self.ssh.execute(cmd)

            if code != 0:
                result.status = "error"
                return result

            lines = [l for l in stdout.strip().split("\n") if l]

            for line in lines:
                match = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(.+)", line)
                if match:
                    timestamp, message = match.groups()

                    entry = LogEntry(
                        timestamp=timestamp,
                        type="Warning",
                        severity="warning",
                        message=message,
                    )
                    result.entries.append(entry)
                    result.warnings += 1

            if result.warnings > 0:
                result.status = "warning"

        except Exception as e:
            self.logger.error(f"check_journalctl_warnings: {e}")
            result.status = "error"

        return result

    def check_auth_log(self) -> CheckResult:
        """Проверка лога аутентификации"""
        result = CheckResult(
            name="auth_log",
            source_name="Лог аутентификации",
            source_path="/var/log/auth.log",
            errors=0,
            warnings=0,
            status="success",
        )

        try:
            cmd = "grep -i fail /var/log/auth.log | tail -20"
            stdout, stderr, code = self.ssh.execute(cmd)

            lines = [l for l in stdout.strip().split("\n") if l and "fail" in l.lower()]

            for line in lines:
                # Парсим timestamp из auth.log
                match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                timestamp = match.group(1) if match else "Unknown"

                entry = LogEntry(
                    timestamp=timestamp,
                    type="Authentication Failure",
                    severity="warning",
                    message=line,
                )
                result.entries.append(entry)
                result.warnings += 1

            if result.warnings > 0:
                result.status = "warning"

        except Exception as e:
            self.logger.error(f"check_auth_log: {e}")
            result.status = "error"

        return result

    def check_fail2ban(self) -> CheckResult:
        """Проверка Fail2ban"""
        result = CheckResult(
            name="fail2ban",
            source_name="Fail2ban (защита от брутфорса)",
            source_path="/var/log/fail2ban.log",
            errors=0,
            warnings=0,
            status="success",
        )

        try:
            cmd = "cat /var/log/fail2ban.log 2>/dev/null | grep -i found"
            stdout, stderr, code = self.ssh.execute(cmd)

            lines = [
                l for l in stdout.strip().split("\n") if l and "found" in l.lower()
            ]

            for line in lines:
                match = re.match(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
                timestamp = match.group(1) if match else "Unknown"

                entry = LogEntry(
                    timestamp=timestamp,
                    type="Suspicious Activity",
                    severity="info",
                    message=line,
                )
                result.entries.append(entry)
                result.warnings += 1

            if result.warnings > 0:
                result.status = "warning"

        except Exception as e:
            self.logger.error(f"check_fail2ban: {e}")
            result.status = "error"

        return result

    def check_corosync(self) -> CheckResult:
        """Проверка Corosync кластера"""
        result = CheckResult(
            name="corosync",
            source_name="Corosync кластер",
            source_path="journalctl -u corosync",
            errors=0,
            warnings=0,
            status="success",
        )

        try:
            cmd = f'journalctl -u corosync --since "{self.period_hours} hours ago" --no-pager | grep -i "no active links\\|link.*down\\|lost quorum"'
            stdout, stderr, code = self.ssh.execute(cmd)

            lines = [l for l in stdout.strip().split("\n") if l]

            for line in lines:
                match = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)", line)
                timestamp = match.group(1) if match else "Unknown"

                severity = "critical" if "lost quorum" in line.lower() else "warning"

                entry = LogEntry(
                    timestamp=timestamp,
                    type="Cluster Issue",
                    severity=severity,
                    message=line,
                )
                result.entries.append(entry)

                if severity == "critical":
                    result.errors += 1
                else:
                    result.warnings += 1

            if result.errors > 0:
                result.status = "error"
            elif result.warnings > 0:
                result.status = "warning"

        except Exception as e:
            self.logger.error(f"check_corosync: {e}")
            result.status = "error"

        return result

    def check_dmesg(self) -> CheckResult:
        """Проверка системных сообщений ядра"""
        result = CheckResult(
            name="dmesg",
            source_name="Системные сообщения ядра",
            source_path="dmesg",
            errors=0,
            warnings=0,
            status="success",
        )

        try:
            cmd = "dmesg -T --level=err,warn 2>/dev/null | tail -50"
            stdout, stderr, code = self.ssh.execute(cmd)

            lines = [l for l in stdout.strip().split("\n") if l]

            for line in lines:
                match = re.match(r"\[([^\]]+)\]", line)
                timestamp = match.group(1) if match else "Unknown"

                severity = "critical" if "error" in line.lower() else "warning"

                entry = LogEntry(
                    timestamp=timestamp,
                    type="Kernel Message",
                    severity=severity,
                    message=line,
                )
                result.entries.append(entry)

                if severity == "critical":
                    result.errors += 1
                else:
                    result.warnings += 1

            if result.errors > 0:
                result.status = "error"
            elif result.warnings > 0:
                result.status = "warning"

        except Exception as e:
            self.logger.error(f"check_dmesg: {e}")
            result.status = "error"

        return result

    def check_pveproxy(self) -> CheckResult:
        """Проверка PVE Proxy (HTTP доступ)"""
        result = CheckResult(
            name="pveproxy",
            source_name="PVE Proxy (HTTP доступ)",
            source_path="/var/log/pveproxy/access.log",
            errors=0,
            warnings=0,
            status="success",
        )

        try:
            cmd = 'tail -100 /var/log/pveproxy/access.log 2>/dev/null | grep -E " (4[0-9]{2}|5[0-9]{2}) "'
            stdout, stderr, code = self.ssh.execute(cmd)

            lines = [l for l in stdout.strip().split("\n") if l]

            for line in lines:
                match = re.search(r" (\d{3}) ", line)
                http_code = match.group(1) if match else "000"

                severity = "critical" if http_code.startswith("5") else "warning"

                entry = LogEntry(
                    timestamp="Recent",
                    type=f"HTTP {http_code}",
                    severity=severity,
                    message=line,
                )
                result.entries.append(entry)

                if severity == "critical":
                    result.errors += 1
                else:
                    result.warnings += 1

            if result.errors > 0:
                result.status = "error"
            elif result.warnings > 0:
                result.status = "warning"

        except Exception as e:
            self.logger.error(f"check_pveproxy: {e}")
            result.status = "error"

        return result

    def check_vms_status(self) -> CheckResult:
        """Проверка статуса виртуальных машин"""
        result = CheckResult(
            name="vms_status",
            source_name="Виртуальные машины (статус)",
            source_path="qm list",
            errors=0,
            warnings=0,
            status="success",
        )

        try:
            cmd = "qm list 2>/dev/null"
            stdout, stderr, code = self.ssh.execute(cmd)

            if code != 0:
                result.status = "error"
                return result

            lines = stdout.strip().split("\n")[1:]  # Пропускаем заголовок

            stopped_vms = []
            running_vms = []

            for line in lines:
                if "stopped" in line.lower():
                    parts = line.split()
                    vm_id = parts[0] if len(parts) > 0 else "Unknown"
                    vm_name = parts[1] if len(parts) > 1 else "Unknown"
                    stopped_vms.append(f"VM {vm_id} ({vm_name})")
                elif "running" in line.lower():
                    parts = line.split()
                    vm_id = parts[0] if len(parts) > 0 else "Unknown"
                    vm_name = parts[1] if len(parts) > 1 else "Unknown"
                    running_vms.append(f"VM {vm_id} ({vm_name})")

            if stopped_vms:
                for vm in stopped_vms:
                    entry = LogEntry(
                        timestamp="Current",
                        type="VM Stopped",
                        severity="info",
                        message=f"{vm} находится в состоянии STOPPED",
                    )
                    result.entries.append(entry)
                    result.warnings += 1

                result.status = "warning"

            result.details["stopped_vms"] = len(stopped_vms)
            result.details["running_vms"] = len(running_vms)
            result.details["total_vms"] = len(stopped_vms) + len(running_vms)

        except Exception as e:
            self.logger.error(f"check_vms_status: {e}")
            result.status = "error"

        return result

    def check_storage(self) -> CheckResult:
        """Проверка дискового пространства через df"""
        result = CheckResult(
            name="storage",
            source_name="Дисковое пространство (df)",
            source_path="df -h",
            errors=0,
            warnings=0,
            status="success",
        )

        try:
            # Используем -P для POSIX совместимости (одна строка на запись)
            # Исключаем tmpfs, devtmpfs, overlay, squashfs чтобы не засорять отчет
            cmd = "df -Ph -x tmpfs -x devtmpfs -x overlay -x squashfs"
            stdout, stderr, code = self.ssh.execute(cmd)

            if code != 0:
                # Если df не сработал, возможно это не Linux или нет флага -x
                # Попробуем просто df -Ph
                cmd = "df -Ph"
                stdout, stderr, code = self.ssh.execute(cmd)
                if code != 0:
                    result.status = "error"
                    return result

            lines = stdout.strip().split("\n")[1:]  # Пропускаем заголовок

            for line in lines:
                parts = line.split()
                if len(parts) < 6:
                    continue

                # df -P format: Filesystem Size Used Avail Capacity Mounted on
                filesystem = parts[0]
                size = parts[1]
                used = parts[2]
                avail = parts[3]
                capacity_str = parts[4].rstrip("%")
                mount_point = parts[5]

                try:
                    # Обработка '-' в выводе df (иногда бывает)
                    if capacity_str == "-":
                        continue

                    usage = float(capacity_str)

                    severity = None
                    if usage > 90:
                        severity = "critical"
                        result.errors += 1
                        result.status = "error"
                    elif usage > 80:
                        severity = "warning"
                        result.warnings += 1
                        if result.status == "success":
                            result.status = "warning"

                    if severity:
                        entry = LogEntry(
                            timestamp="Current",
                            type="Disk Usage",
                            severity=severity,
                            message=f"Раздел {mount_point} ({filesystem}): {usage}% использовано ({used}/{size})",
                        )
                        result.entries.append(entry)

                        result.details[mount_point] = {
                            "filesystem": filesystem,
                            "usage": usage,
                            "size": size,
                            "used": used,
                            "avail": avail,
                        }

                except ValueError:
                    continue

        except Exception as e:
            self.logger.error(f"check_storage: {e}")
            result.status = "error"

        return result

    def check_cluster(self) -> CheckResult:
        """Проверка кластера Proxmox"""
        result = CheckResult(
            name="cluster",
            source_name="Кластер Proxmox (кворум)",
            source_path="pvecm status",
            errors=0,
            warnings=0,
            status="success",
        )

        try:
            cmd = "pvecm status 2>/dev/null"
            stdout, stderr, code = self.ssh.execute(cmd)

            if code != 0:
                result.status = "error"
                return result

            # Парсим вывод pvecm status
            quorate = "No"
            expected_votes = 0
            total_votes = 0

            for line in stdout.split("\n"):
                if "Quorate:" in line:
                    quorate = line.split(":")[1].strip()
                elif "Expected votes:" in line:
                    expected_votes = int(line.split(":")[1].strip())
                elif "Total votes:" in line:
                    total_votes = int(line.split(":")[1].strip())

            if quorate != "Yes":
                entry = LogEntry(
                    timestamp="Current",
                    type="Cluster Quorum Lost",
                    severity="critical",
                    message=f"Кластер потерял кворум! Expected: {expected_votes}, Total: {total_votes}",
                )
                result.entries.append(entry)
                result.errors += 1
                result.status = "error"
            else:
                entry = LogEntry(
                    timestamp="Current",
                    type="Cluster OK",
                    severity="info",
                    message=f"Кворум достигнут. Votes: {total_votes}/{expected_votes}",
                )
                result.entries.append(entry)

            result.details["quorate"] = quorate
            result.details["expected_votes"] = expected_votes
            result.details["total_votes"] = total_votes

        except Exception as e:
            self.logger.error(f"check_cluster: {e}")
            result.status = "error"

        return result

    def check_zfs_snapshots(
        self, cleanup_threshold: Optional[int] = None
    ) -> CheckResult:
        """Проверка ZFS снимков и автоочистка"""
        result = CheckResult(
            name="zfs_snapshots",
            source_name="ZFS снимки",
            source_path="zfs list -t snapshot",
            errors=0,
            warnings=0,
            status="success",
        )

        try:
            # Получаем список пулов со статусом
            cmd = "pvesm status 2>/dev/null | grep zfspool"
            stdout, stderr, code = self.ssh.execute(cmd)

            if code != 0:
                return result

            pools_to_clean = []

            for line in stdout.strip().split("\n"):
                if not line:
                    continue

                parts = line.split()
                if len(parts) < 6:
                    continue

                pool_name = parts[0]
                usage_percent = parts[5].rstrip("%")

                try:
                    usage = float(usage_percent)

                    if cleanup_threshold and usage > cleanup_threshold:
                        pools_to_clean.append((pool_name, usage))

                except ValueError:
                    continue

            # Выполняем очистку для каждого пула
            for pool_name, initial_usage in pools_to_clean:
                self.logger.info(
                    f"{pool_name}: {initial_usage}% > {cleanup_threshold}%, запуск очистки..."
                )

                cleaned = False
                iterations = 0
                max_iterations = 5

                current_usage = initial_usage

                while current_usage > cleanup_threshold and iterations < max_iterations:
                    iterations += 1

                    # Удаляем 10 самых больших снимков (исключая replicate)
                    cleanup_cmd = (
                        f"zfs list -t snapshot -o name -s used {pool_name} | "
                        f"tail -n 10 | grep -v replicate | "
                        f'while read -r line; do zfs destroy "$line" 2>/dev/null; done'
                    )

                    stdout, stderr, code = self.ssh.execute(cleanup_cmd)

                    # Проверяем новое использование
                    check_cmd = f'pvesm status 2>/dev/null | grep "^{pool_name} "'
                    stdout, stderr, code = self.ssh.execute(check_cmd)

                    if code == 0 and stdout:
                        parts = stdout.split()
                        if len(parts) >= 6:
                            new_usage_str = parts[5].rstrip("%")
                            try:
                                new_usage = float(new_usage_str)

                                self.logger.info(
                                    f"  Итерация {iterations}: {current_usage}% -> {new_usage}%"
                                )

                                if new_usage < current_usage:
                                    cleaned = True
                                    current_usage = new_usage
                                else:
                                    break  # Нет смысла продолжать

                            except ValueError:
                                break

                if cleaned:
                    entry = LogEntry(
                        timestamp="Current",
                        type="ZFS Cleanup",
                        severity="info",
                        message=f"{pool_name}: очистка завершена за {iterations} итераций, {initial_usage}% -> {current_usage}%",
                    )
                    result.entries.append(entry)
                    result.warnings += 1
                    result.status = "warning"

                    result.details[pool_name] = {
                        "initial_usage": initial_usage,
                        "final_usage": current_usage,
                        "iterations": iterations,
                        "freed": initial_usage - current_usage,
                    }

        except Exception as e:
            self.logger.error(f"check_zfs_snapshots: {e}")
            result.status = "error"

        return result

    def get_uptime(self) -> str:
        """Получить uptime сервера"""
        try:
            stdout, stderr, code = self.ssh.execute("uptime -p")
            if code == 0:
                return stdout.strip()
        except:
            pass
        return "Unknown"

    def get_load_average(self) -> str:
        """Получить load average"""
        try:
            stdout, stderr, code = self.ssh.execute("uptime")
            if code == 0:
                match = re.search(r"load average: ([\d\., ]+)", stdout)
                if match:
                    return match.group(1)
        except:
            pass
        return "Unknown"


def check_server(hostname: str, args: argparse.Namespace) -> ServerReport:
    """Проверка одного сервера"""
    # Парсим user@host формат
    parsed_hostname, parsed_username = parse_host_string(hostname)
    
    # Используем пользователя из hostname если указан, иначе из --ssh-user
    effective_username = parsed_username if parsed_username else args.ssh_user
    
    logger = logging.getLogger(f"[{hostname}]")
    logger.info("Начало проверки...")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Подключаемся к серверу
    ssh = SSHConnection(
        hostname=parsed_hostname,
        username=effective_username,
        ssh_config=args.ssh_config,
        timeout=args.ssh_timeout,
        password=getattr(args, "password", None),
    )

    success, error = ssh.connect()

    # Если не удалось подключиться по ключу и пароль не был задан -
    # запрашиваем пароль интерактивно
    if not success and not getattr(args, "password", None):
        if "authentication" in error.lower() or "no authentication" in error.lower():
            logger.warning(f"⚠️  Аутентификация по ключу не удалась: {error}")
            logger.info("🔐 Попытка аутентификации по паролю...")
            
            try:
                password = getpass.getpass(
                    f"   Введите пароль для {effective_username}@{parsed_hostname}: "
                )
                if password:
                    # Сохраняем пароль для последующих серверов
                    args.password = password
                    
                    # Пробуем подключиться с паролем
                    ssh = SSHConnection(
                        hostname=parsed_hostname,
                        username=effective_username,
                        ssh_config=args.ssh_config,
                        timeout=args.ssh_timeout,
                        password=password,
                    )
                    success, error = ssh.connect()
            except KeyboardInterrupt:
                logger.warning("\n⚠️  Отменено пользователем")
                return ServerReport(
                    hostname=hostname,
                    timestamp=timestamp,
                    period_hours=args.period,
                    connection_error="Отменено пользователем",
                    checks=[],
                )

    if not success:
        # Создаём отчёт с ошибкой подключения
        logger.error(f"Не удалось подключиться: {error}")
        return ServerReport(
            hostname=hostname,
            timestamp=timestamp,
            period_hours=args.period,
            connection_error=error,
            checks=[],
        )

    # Создаём объект для проверок
    checks = ServerChecks(ssh, args.period)

    # Список всех проверок
    # Список всех проверок
    check_functions = [
        checks.check_journalctl_errors,
        checks.check_journalctl_warnings,
        checks.check_auth_log,
        checks.check_dmesg,
        checks.check_fail2ban,
        checks.check_storage,
        checks.check_corosync,
        checks.check_pveproxy,
        checks.check_vms_status,
        checks.check_cluster,
    ]

    # Добавляем проверку ZFS снимков если указан threshold
    if args.cleanup_threshold:
        check_functions.append(
            lambda: checks.check_zfs_snapshots(args.cleanup_threshold)
        )

    logger.info(f"Запуск {len(check_functions)} проверок ({args.parallel} потоков)...")

    # Выполняем проверки параллельно
    results = []
    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        future_to_check = {
            executor.submit(func): func.__name__ for func in check_functions
        }

        for future in as_completed(future_to_check):
            check_name = future_to_check[future]
            try:
                result = future.result()
                results.append(result)

                status_icon = (
                    "✓"
                    if result.status == "success"
                    else "⚠️"
                    if result.status == "warning"
                    else "✗"
                )
                logger.info(
                    f"  {status_icon} {result.source_name} ({result.errors} ошибок, {result.warnings} предупреждений)"
                )

            except Exception as e:
                logger.error(f"  ✗ {check_name}: {e}")

    # Получаем системную информацию
    uptime = checks.get_uptime()
    load_average = checks.get_load_average()

    # Закрываем соединение
    ssh.close()

    # Подсчитываем общее количество ошибок и предупреждений
    total_errors = sum(r.errors for r in results)
    total_warnings = sum(r.warnings for r in results)

    logger.info(
        f"✅ Проверка завершена: {total_errors} ошибок, {total_warnings} предупреждений"
    )

    return ServerReport(
        hostname=hostname,
        timestamp=timestamp,
        period_hours=args.period,
        connection_error=None,
        checks=results,
        total_errors=total_errors,
        total_warnings=total_warnings,
        uptime=uptime,
        load_average=load_average,
    )


class AIOutputGenerator:
    """Генератор AI-friendly вывода"""

    SEVERITY_ORDER = {"critical": 0, "error": 1, "warning": 2, "info": 3}

    def __init__(self, reports: List[ServerReport], args: argparse.Namespace):
        self.reports = reports
        self.args = args
        self.start_time = datetime.now()

    def categorize_entry(self, entry: LogEntry, check_name: str = "") -> str:
        """Определить категорию записи лога"""
        message_lower = entry.message.lower()

        for category, patterns in CATEGORY_PATTERNS.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, message_lower, re.IGNORECASE):
                        return category
                except re.error:
                    continue

        # Определяем категорию по типу проверки
        check_to_category = {
            "storage": "storage",
            "journalctl_errors": "services",
            "journalctl_warnings": "services",
            "auth_log": "authentication",
            "fail2ban": "authentication",
            "dmesg": "kernel",
            "corosync": "cluster",
            "cluster": "cluster",
            "pveproxy": "services",
            "vms_status": "virtualization",
            "zfs_snapshots": "storage",
        }

        return check_to_category.get(check_name, "other")

    def _get_severity_priority(self, severity: str) -> int:
        """Получить приоритет severity (меньше = важнее)"""
        return self.SEVERITY_ORDER.get(severity.lower(), 99)

    def _passes_severity_filter(self, severity: str) -> bool:
        """Проверить, проходит ли severity минимальный фильтр"""
        min_severity = getattr(self.args, "min_severity", "warning")
        severity_threshold = self._get_severity_priority(min_severity)
        entry_priority = self._get_severity_priority(severity)
        return entry_priority <= severity_threshold

    def _get_server_status(self, report: ServerReport) -> str:
        """Определить статус сервера"""
        if report.connection_error:
            return "unreachable"
        if report.total_errors > 0:
            return "critical"
        if report.total_warnings > 0:
            return "warning"
        return "ok"

    def _get_overall_status(self) -> str:
        """Определить общий статус всех серверов"""
        statuses = [self._get_server_status(r) for r in self.reports]
        if "unreachable" in statuses or "critical" in statuses:
            return "critical"
        if "warning" in statuses:
            return "warning"
        return "ok"

    def _collect_all_issues(self) -> List[Dict]:
        """Собрать все проблемы со всех серверов"""
        all_issues = []

        for report in self.reports:
            if report.connection_error:
                all_issues.append({
                    "server": report.hostname,
                    "category": "connection",
                    "message": report.connection_error,
                    "severity": "critical",
                    "count": 1,
                    "check_name": "connection"
                })
                continue

            for check in report.checks:
                for entry in check.entries:
                    if not self._passes_severity_filter(entry.severity):
                        continue

                    category = self.categorize_entry(entry, check.name)
                    all_issues.append({
                        "server": report.hostname,
                        "category": category,
                        "message": entry.message,
                        "severity": entry.severity,
                        "count": 1,
                        "check_name": check.name,
                        "timestamp": entry.timestamp
                    })

        return all_issues

    def _group_issues_by_category(self, issues: List[Dict]) -> Dict[str, Dict]:
        """Группировать проблемы по категориям"""
        categories = {}

        for issue in issues:
            cat = issue["category"]
            if cat not in categories:
                categories[cat] = {
                    "total_count": 0,
                    "max_severity": "info",
                    "affected_servers": set(),
                    "examples": []
                }

            categories[cat]["total_count"] += 1
            categories[cat]["affected_servers"].add(issue["server"])

            # Обновляем max_severity
            if self._get_severity_priority(issue["severity"]) < \
               self._get_severity_priority(categories[cat]["max_severity"]):
                categories[cat]["max_severity"] = issue["severity"]

            # Добавляем примеры (максимум 3)
            if len(categories[cat]["examples"]) < 3:
                example = f"{issue['server']}: {issue['message'][:100]}"
                if example not in categories[cat]["examples"]:
                    categories[cat]["examples"].append(example)

        # Преобразуем set в list
        for cat in categories:
            categories[cat]["affected_servers"] = list(categories[cat]["affected_servers"])

        return categories

    def _get_critical_issues(self, issues: List[Dict]) -> List[Dict]:
        """Получить список критических проблем"""
        critical = []
        for issue in issues:
            if issue["severity"] in ("critical", "error"):
                critical.append({
                    "server": issue["server"],
                    "category": issue["category"],
                    "message": issue["message"][:200],
                    "severity": issue["severity"],
                    "count": issue.get("count", 1)
                })
        return critical[:20]  # Максимум 20 критических проблем

    def _build_server_summary(self, report: ServerReport, issues: List[Dict]) -> Dict:
        """Построить сводку по серверу"""
        server_issues = [i for i in issues if i["server"] == report.hostname]
        categories_affected = list(set(i["category"] for i in server_issues))

        # Top issues - самые важные проблемы
        top_issues = []
        critical_issues = [i for i in server_issues if i["severity"] in ("critical", "error")]
        for issue in critical_issues[:5]:
            top_issues.append({
                "category": issue["category"],
                "message": issue["message"][:150],
                "severity": issue["severity"]
            })

        return {
            "status": self._get_server_status(report),
            "connection_error": report.connection_error,
            "hostname": report.hostname,
            "uptime": report.uptime,
            "load_average": report.load_average,
            "errors": report.total_errors,
            "warnings": report.total_warnings,
            "categories_affected": categories_affected,
            "top_issues": top_issues
        }

    def _build_detailed_logs(self) -> Dict:
        """Построить детальные логи для формата full"""
        detailed = {}

        for report in self.reports:
            if report.connection_error:
                detailed[report.hostname] = {"connection_error": report.connection_error}
                continue

            server_data = {}
            for check in report.checks:
                check_data = {
                    "status": check.status,
                    "errors": check.errors,
                    "warnings": check.warnings,
                    "entries": []
                }

                grouped = group_entries(check.entries)
                for group in grouped:
                    if not self._passes_severity_filter(group.entry.severity):
                        continue

                    check_data["entries"].append({
                        "count": group.count,
                        "first_timestamp": group.first_timestamp,
                        "last_timestamp": group.last_timestamp,
                        "type": group.entry.type,
                        "severity": group.custom_severity or group.entry.severity,
                        "message": group.group_message,
                        "category": self.categorize_entry(group.entry, check.name)
                    })

                if check_data["entries"] or check.status != "success":
                    server_data[check.name] = check_data

            detailed[report.hostname] = server_data

        return detailed

    def generate(self) -> Dict:
        """Генерация AI-friendly вывода"""
        all_issues = self._collect_all_issues()
        issues_by_category = self._group_issues_by_category(all_issues)
        critical_issues = self._get_critical_issues(all_issues)

        servers_ok = sum(1 for r in self.reports if self._get_server_status(r) == "ok")
        servers_warning = sum(1 for r in self.reports if self._get_server_status(r) == "warning")
        servers_critical = sum(1 for r in self.reports if self._get_server_status(r) == "critical")
        servers_unreachable = sum(1 for r in self.reports if self._get_server_status(r) == "unreachable")

        output = {
            "format_version": "2.0",
            "format_type": getattr(self.args, "ai_format", "standard"),
            "generated_at": datetime.now().isoformat(),
            "check_params": {
                "period_hours": self.args.period,
                "servers_requested": [r.hostname for r in self.reports],
                "min_severity": getattr(self.args, "min_severity", "warning")
            },
            "summary": {
                "overall_status": self._get_overall_status(),
                "servers_total": len(self.reports),
                "servers_ok": servers_ok,
                "servers_warning": servers_warning,
                "servers_critical": servers_critical,
                "servers_unreachable": servers_unreachable,
                "total_errors": sum(r.total_errors for r in self.reports),
                "total_warnings": sum(r.total_warnings for r in self.reports)
            },
            "critical_issues": critical_issues,
            "issues_by_category": issues_by_category,
            "servers": {}
        }

        # Добавляем сводку по каждому серверу
        for report in self.reports:
            output["servers"][report.hostname] = self._build_server_summary(report, all_issues)

        # Для формата full добавляем детальные логи
        if getattr(self.args, "ai_format", "standard") == "full":
            output["detailed_logs"] = self._build_detailed_logs()

        return output

    def to_compact_json(self) -> str:
        """Компактный JSON для минимизации токенов"""
        full_output = self.generate()

        # Формируем краткую сводку
        summary = full_output["summary"]
        status_parts = []
        if summary["servers_critical"] > 0:
            status_parts.append(f"{summary['servers_critical']} critical")
        if summary["servers_warning"] > 0:
            status_parts.append(f"{summary['servers_warning']} warning")
        if summary["servers_ok"] > 0:
            status_parts.append(f"{summary['servers_ok']} ok")
        if summary["servers_unreachable"] > 0:
            status_parts.append(f"{summary['servers_unreachable']} unreachable")

        summary_text = f"{summary['servers_total']} servers: {', '.join(status_parts)}"
        summary_text += f" | {summary['total_errors']} errors, {summary['total_warnings']} warnings"

        # Критические проблемы в виде строк
        critical_strs = []
        for issue in full_output["critical_issues"][:10]:
            critical_strs.append(f"{issue['server']}: {issue['category']} - {issue['message'][:80]}")

        compact = {
            "format_version": "2.0",
            "format_type": "compact",
            "status": summary["overall_status"],
            "summary": summary_text,
            "critical_issues": critical_strs,
            "servers_status": {
                hostname: data["status"]
                for hostname, data in full_output["servers"].items()
            }
        }

        return json.dumps(compact, ensure_ascii=False, indent=2)

    def to_json(self) -> str:
        """Стандартный JSON вывод"""
        output = self.generate()
        return json.dumps(output, ensure_ascii=False, indent=2)


def generate_html_report(report: ServerReport, output_file: str):
    """Генерация HTML отчёта"""

    # Определяем директорию шаблонов
    templates_dir = get_resource_path("templates")

    # Если шаблон существует, используем Jinja2
    if (templates_dir / "report_template.html").exists():
        env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("report_template.html")
        html_content = template.render(report=report, group_entries=group_entries)
    else:
        # Иначе генерируем HTML напрямую
        html_content = generate_html_inline(report)

    # Сохраняем файл
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_html_inline(report: ServerReport) -> str:
    """Генерация HTML без шаблона (стиль как в оригинальном артефакте)"""

    # Полный CSS из оригинального артефакта
    css = """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .summary-card .number {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .summary-card.errors .number {
            color: #dc3545;
        }
        
        .summary-card.warnings .number {
            color: #ffc107;
        }
        
        .summary-card.checked .number {
            color: #28a745;
        }
        
        .summary-card .label {
            font-size: 13px;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background: #495057;
            color: white;
        }
        
        th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        th.center, td.center {
            text-align: center;
        }
        
        tbody tr {
            border-bottom: 1px solid #e9ecef;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        tbody tr:hover {
            background: #f8f9fa;
        }
        
        tbody tr.expanded {
            background: #e7f3ff;
        }
        
        td {
            padding: 15px;
        }
        
        .source-name {
            font-weight: 600;
            color: #212529;
        }
        
        .source-path {
            font-size: 12px;
            color: #6c757d;
            font-family: 'Courier New', monospace;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge.error {
            background: #fee;
            color: #dc3545;
        }
        
        .badge.warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge.success {
            background: #d4edda;
            color: #155724;
        }
        
        .expand-icon {
            display: inline-block;
            width: 20px;
            height: 20px;
            line-height: 20px;
            text-align: center;
            background: #6c757d;
            color: white;
            border-radius: 4px;
            font-size: 12px;
            margin-right: 10px;
            transition: transform 0.3s;
        }
        
        tr.expanded .expand-icon {
            transform: rotate(90deg);
            background: #007bff;
        }
        
        .details {
            display: none;
            background: #f8f9fa;
        }
        
        .details.show {
            display: table-row;
        }
        
        .details td {
            padding: 0;
        }
        
        .details-content {
            padding: 20px 30px;
            background: white;
            margin: 10px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }
        
        .error-item {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            padding: 8px 12px;
            margin-bottom: 8px;
        }
        
        .error-item:last-child {
            margin-bottom: 0;
        }
        
        .error-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }
        
        .error-type {
            font-weight: 600;
            color: #212529;
            font-size: 13px;
        }
        
        .error-time {
            font-size: 11px;
            color: #6c757d;
            font-family: 'Courier New', monospace;
        }
        
        .error-message {
            background: #f8f9fa;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #495057;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.4;
            text-align: left;
        }
        
        .error-severity {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            margin-left: 10px;
        }
        
        .severity-critical {
            background: #dc3545;
            color: white;
        }
        
        .severity-warning {
            background: #ffc107;
            color: #000;
        }
        
        .severity-info {
            background: #17a2b8;
            color: white;
        }
        
        .count-badge {
            background: #6c757d;
            color: white;
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 11px;
            margin-right: 8px;
            font-weight: bold;
            vertical-align: middle;
        }
        
        .no-errors {
            text-align: center;
            padding: 30px;
            color: #28a745;
            font-weight: 600;
        }
        
        .footer {
            padding: 20px 30px;
            background: #f8f9fa;
            text-align: center;
            font-size: 12px;
            color: #6c757d;
            border-top: 1px solid #e9ecef;
        }
    """

    # Генерируем HTML
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет по логам {report.hostname}</title>
    <style>
{css}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Отчет по логам сервера {report.hostname}</h1>
            <div class="subtitle">Анализ за {report.period_hours} часов • {report.timestamp}</div>
        </div>
"""

    if report.connection_error:
        html += f"""
        <div class="connection-error">
            <h2>❌ Ошибка подключения к серверу</h2>
            <p>{report.connection_error}</p>
        </div>
"""
    else:
        html += f"""
        <div class="summary">
            <div class="summary-card errors">
                <div class="number">{report.total_errors}</div>
                <div class="label">Ошибок</div>
            </div>
            <div class="summary-card warnings">
                <div class="number">{report.total_warnings}</div>
                <div class="label">Предупреждений</div>
            </div>
            <div class="summary-card checked">
                <div class="number">{len(report.checks)}</div>
                <div class="label">Источников проверено</div>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Источник</th>
                    <th class="center">Ошибки</th>
                    <th class="center">Предупреждения</th>
                    <th class="center">Статус</th>
                </tr>
            </thead>
            <tbody>
"""

        for check in report.checks:
            # Определяем статус
            if check.errors > 0:
                status_text = "Найдены ошибки"
                status_class = "error"
            elif check.warnings > 0:
                status_text = "Есть предупреждения"
                status_class = "warning"
            else:
                status_text = "Ошибок нет"
                status_class = "success"

            html += f"""
                <tr onclick="toggleRow(this)">
                    <td>
                        <span class="expand-icon">▶</span>
                        <div class="source-name">{check.source_name}</div>
                        <div class="source-path">{check.source_path}</div>
                    </td>
                    <td class="center">
                        <span class="badge {"error" if check.errors > 0 else "success"}">{check.errors}</span>
                    </td>
                    <td class="center">
                        <span class="badge {"warning" if check.warnings > 0 else "success"}">{check.warnings}</span>
                    </td>
                    <td class="center">
                        <span class="badge {status_class}">{status_text}</span>
                    </td>
                </tr>
                <tr class="details">
                    <td colspan="4">
                        <div class="details-content">
"""

            if check.entries:
                grouped_entries = group_entries(check.entries)
                for group in grouped_entries:
                    count_html = ""
                    if group.count > 1:
                        count_html = f'<span class="count-badge">{group.count}x</span>'

                    timestamp_display = group.entry.timestamp
                    if (
                        group.count > 1
                        and group.first_timestamp != group.last_timestamp
                    ):
                        timestamp_display = (
                            f"{group.first_timestamp} ... {group.last_timestamp}"
                        )

                    # Формируем список деталей
                    details_html = '<div class="error-details-list" onclick="event.stopPropagation()">'
                    for entry in group.all_entries:
                        details_html += f"""
                                <div class="sub-error">
                                    <span class="sub-error-time">{entry.timestamp}</span>
                                    <span class="sub-error-msg">{entry.message}</span>
                                </div>
                        """
                    details_html += "</div>"

                    html += f"""
                            <div class="error-item clickable" onclick="toggleErrorDetails(this)">
                                <div class="error-header">
                                    <span class="error-type">
                                        {count_html}
                                        {group.entry.type}
                                        <span class="error-severity severity-{group.entry.severity}">{group.entry.severity}</span>
                                    </span>
                                    <span class="error-time">{timestamp_display}</span>
                                </div>
                                <div class="error-message">{group.group_message}</div>
                                {details_html}
                            </div>
"""
            else:
                html += """
                            <div class="no-errors">✅ Ошибок и предупреждений не обнаружено</div>
"""

            html += """
                        </div>
                    </td>
                </tr>
"""

        html += """
            </tbody>
        </table>
"""

    html += f"""
        <div class="footer">
            Отчет сгенерирован автоматически • {report.hostname} • {report.timestamp}
        </div>
    </div>
    
    <script>
        function toggleRow(row) {{
            const detailsRow = row.nextElementSibling;
            const icon = row.querySelector('.expand-icon');
            
            // Toggle expanded class
            row.classList.toggle('expanded');
            
            // Toggle details visibility
            detailsRow.classList.toggle('show');
        }}
        
        function toggleErrorDetails(element) {{
            const detailsList = element.querySelector('.error-details-list');
            if (detailsList) {{
                if (detailsList.style.display === 'block') {{
                    detailsList.style.display = 'none';
                }} else {{
                    detailsList.style.display = 'block';
                }}
            }}
        }}
    </script>
</body>
</html>
"""

    return html


# ============================================================================
# Функции для генерации сводного отчёта index.html
# ============================================================================

def extract_environment_domain(hostname: str) -> str:
    """
    Извлекает домен среды из hostname.
    
    Примеры:
        server1.prod.example.com -> prod.example.com
        db1.staging.example.com -> staging.example.com
        web1.internal.corp -> internal.corp
        simple-server -> simple-server (без домена)
        192.168.1.100 -> 192.168.1.100 (IP-адрес)
    
    Args:
        hostname: полное имя хоста
        
    Returns:
        Домен среды или исходный hostname если домен не определён
    """
    # Убираем user@ если есть
    if '@' in hostname:
        hostname = hostname.split('@', 1)[1]
    
    # Проверяем, является ли это IP-адресом
    ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, hostname):
        return hostname
    
    # Разделяем по точкам
    parts = hostname.split('.')
    
    # Если только одна часть (например, "localhost") - возвращаем как есть
    if len(parts) <= 1:
        return hostname
    
    # Если две части (например, "server.local") - возвращаем как есть
    if len(parts) == 2:
        return hostname
    
    # Если три и более частей - убираем первую (имя сервера)
    # server1.prod.example.com -> prod.example.com
    return '.'.join(parts[1:])


def parse_report_filename(filepath: Path) -> Optional[ReportFileInfo]:
    """
    Парсит имя файла отчёта и извлекает метаданные.
    
    Формат имени: report_HOSTNAME_YYYY-MM-DD_HH-MM.html
    
    Args:
        filepath: путь к файлу отчёта
        
    Returns:
        ReportFileInfo или None если не удалось распарсить
    """
    filename = filepath.name
    
    # Паттерн для имени файла: report_HOSTNAME_YYYY-MM-DD_HH-MM.html
    # HOSTNAME может содержать точки, дефисы и @ (для user@host)
    pattern = r'^report_(.+)_(\d{4}-\d{2}-\d{2})_(\d{2}-\d{2})\.html$'
    match = re.match(pattern, filename)
    
    if not match:
        return None
    
    hostname = match.group(1)
    date_str = match.group(2)  # YYYY-MM-DD
    time_str = match.group(3).replace('-', ':')  # HH:MM
    
    try:
        timestamp = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
    except ValueError:
        return None
    
    domain_group = extract_environment_domain(hostname)
    
    return ReportFileInfo(
        filepath=filepath,
        hostname=hostname,
        timestamp=timestamp,
        date_str=date_str,
        time_str=time_str,
        domain_group=domain_group
    )


def extract_report_metadata(filepath: Path) -> Optional[ReportMetadata]:
    """
    Извлекает метаданные из HTML отчёта.
    
    Парсит HTML и извлекает количество ошибок, предупреждений и статус.
    
    Args:
        filepath: путь к файлу отчёта
        
    Returns:
        ReportMetadata или None если не удалось извлечь
    """
    try:
        # Пробуем разные кодировки
        content = None
        for encoding in ['utf-8', 'cp1251', 'latin-1']:
            try:
                with open(filepath, 'r', encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            logging.warning(f"Не удалось прочитать файл {filepath} ни в одной кодировке")
            return None
        
        # Извлекаем hostname из заголовка
        hostname_match = re.search(r'Отчет по логам сервера ([^<]+)', content)
        hostname = hostname_match.group(1).strip() if hostname_match else "Unknown"
        
        # Извлекаем период
        period_match = re.search(r'Анализ за (\d+) часов', content)
        period_hours = int(period_match.group(1)) if period_match else 24
        
        # Извлекаем timestamp
        timestamp_match = re.search(r'Анализ за \d+ часов • ([^<]+)', content)
        timestamp = timestamp_match.group(1).strip() if timestamp_match else ""
        
        # Проверяем на ошибку подключения
        if 'Ошибка подключения к серверу' in content:
            return ReportMetadata(
                hostname=hostname,
                timestamp=timestamp,
                total_errors=0,
                total_warnings=0,
                status='connection_error',
                period_hours=period_hours
            )
        
        # Извлекаем количество ошибок
        errors_match = re.search(r'class="summary-card errors"[^>]*>\s*<div class="number">(\d+)</div>', content)
        total_errors = int(errors_match.group(1)) if errors_match else 0
        
        # Извлекаем количество предупреждений
        warnings_match = re.search(r'class="summary-card warnings"[^>]*>\s*<div class="number">(\d+)</div>', content)
        total_warnings = int(warnings_match.group(1)) if warnings_match else 0
        
        # Определяем статус
        if total_errors > 0:
            status = 'error'
        elif total_warnings > 0:
            status = 'warning'
        else:
            status = 'success'
        
        return ReportMetadata(
            hostname=hostname,
            timestamp=timestamp,
            total_errors=total_errors,
            total_warnings=total_warnings,
            status=status,
            period_hours=period_hours
        )
        
    except Exception as e:
        logging.warning(f"Не удалось извлечь метаданные из {filepath}: {e}")
        return None


def scan_reports_directory(reports_dir: Path) -> List[Tuple[ReportFileInfo, Optional[ReportMetadata]]]:
    """
    Сканирует каталог и возвращает список всех отчётов с метаданными.
    
    Args:
        reports_dir: путь к каталогу с отчётами
        
    Returns:
        Список кортежей (ReportFileInfo, ReportMetadata)
    """
    reports = []
    
    if not reports_dir.exists():
        return reports
    
    for filepath in reports_dir.glob('report_*.html'):
        # Пропускаем index.html
        if filepath.name == 'index.html':
            continue
            
        file_info = parse_report_filename(filepath)
        if file_info is None:
            continue
        
        metadata = extract_report_metadata(filepath)
        reports.append((file_info, metadata))
    
    # Сортируем по дате (новые сначала), затем по домену, затем по hostname
    reports.sort(key=lambda x: (x[0].date_str, x[0].domain_group, x[0].hostname), reverse=True)
    
    return reports


def group_reports_by_date_and_domain(
    reports: List[Tuple[ReportFileInfo, Optional[ReportMetadata]]]
) -> Dict[str, Dict[str, List[Tuple[ReportFileInfo, Optional[ReportMetadata]]]]]:
    """
    Группирует отчёты по дате и домену.
    
    Returns:
        Словарь вида {date_str: {domain_group: [(file_info, metadata), ...]}}
    """
    grouped: Dict[str, Dict[str, List]] = {}
    
    for file_info, metadata in reports:
        date_str = file_info.date_str
        domain = file_info.domain_group
        
        if date_str not in grouped:
            grouped[date_str] = {}
        
        if domain not in grouped[date_str]:
            grouped[date_str][domain] = []
        
        grouped[date_str][domain].append((file_info, metadata))
    
    return grouped


def generate_index_html(reports_dir: Path):
    """
    Генерирует index.html со ссылками на все отчёты.
    
    Args:
        reports_dir: путь к каталогу с отчётами
    """
    logger = logging.getLogger("IndexGenerator")
    
    # Сканируем каталог
    reports = scan_reports_directory(reports_dir)
    
    if not reports:
        logger.info("Нет отчётов для index.html")
        return
    
    # Группируем по дате и домену
    grouped = group_reports_by_date_and_domain(reports)
    
    # Считаем общую статистику
    total_reports = len(reports)
    total_errors = sum(m.total_errors if m else 0 for _, m in reports)
    total_warnings = sum(m.total_warnings if m else 0 for _, m in reports)
    servers_with_errors = sum(1 for _, m in reports if m and m.status == 'error')
    servers_ok = sum(1 for _, m in reports if m and m.status == 'success')
    servers_warning = sum(1 for _, m in reports if m and m.status == 'warning')
    servers_unreachable = sum(1 for _, m in reports if m and m.status == 'connection_error')
    
    # Определяем директорию шаблонов
    templates_dir = get_resource_path("templates")
    
    # Пробуем использовать шаблон
    if (templates_dir / "index_template.html").exists():
        env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("index_template.html")
        html_content = template.render(
            grouped=grouped,
            total_reports=total_reports,
            total_errors=total_errors,
            total_warnings=total_warnings,
            servers_with_errors=servers_with_errors,
            servers_ok=servers_ok,
            servers_warning=servers_warning,
            servers_unreachable=servers_unreachable,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    else:
        # Генерируем inline
        html_content = generate_index_html_inline(
            grouped, total_reports, total_errors, total_warnings,
            servers_with_errors, servers_ok, servers_warning, servers_unreachable
        )
    
    # Сохраняем файл
    index_path = reports_dir / "index.html"
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    logger.info(f"📋 Сводный отчёт сохранён: {index_path}")


def generate_index_html_inline(
    grouped: Dict[str, Dict[str, List]],
    total_reports: int,
    total_errors: int,
    total_warnings: int,
    servers_with_errors: int,
    servers_ok: int,
    servers_warning: int,
    servers_unreachable: int
) -> str:
    """Генерация index.html без шаблона"""
    
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    css = """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }
        
        .summary-card {
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .summary-card .number {
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .summary-card.errors .number { color: #dc3545; }
        .summary-card.warnings .number { color: #ffc107; }
        .summary-card.ok .number { color: #28a745; }
        .summary-card.total .number { color: #6c757d; }
        
        .summary-card .label {
            font-size: 12px;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .date-section {
            border-bottom: 1px solid #e9ecef;
        }
        
        .date-header {
            background: #495057;
            color: white;
            padding: 12px 20px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .date-header:hover {
            background: #5a6268;
        }
        
        .date-header .expand-icon {
            transition: transform 0.3s;
        }
        
        .date-header.collapsed .expand-icon {
            transform: rotate(-90deg);
        }
        
        .date-content {
            display: block;
        }
        
        .date-content.collapsed {
            display: none;
        }
        
        .domain-section {
            border-left: 4px solid #007bff;
            margin: 10px 20px;
            background: #f8f9fa;
            border-radius: 0 8px 8px 0;
        }
        
        .domain-header {
            padding: 10px 15px;
            font-weight: 600;
            color: #495057;
            background: #e9ecef;
            border-radius: 0 8px 0 0;
        }
        
        .domain-header .domain-icon {
            margin-right: 8px;
        }
        
        .server-list {
            padding: 10px 15px;
        }
        
        .server-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 15px;
            margin-bottom: 8px;
            background: white;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .server-item:hover {
            transform: translateX(5px);
            box-shadow: 0 2px 6px rgba(0,0,0,0.15);
        }
        
        .server-item:last-child {
            margin-bottom: 0;
        }
        
        .server-info {
            flex: 1;
        }
        
        .server-name {
            font-weight: 600;
            color: #212529;
            text-decoration: none;
        }
        
        .server-name:hover {
            color: #007bff;
            text-decoration: underline;
        }
        
        .server-time {
            font-size: 12px;
            color: #6c757d;
            margin-top: 2px;
        }
        
        .server-stats {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }
        
        .badge.error {
            background: #fee;
            color: #dc3545;
        }
        
        .badge.warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge.success {
            background: #d4edda;
            color: #155724;
        }
        
        .badge.unreachable {
            background: #e2e3e5;
            color: #6c757d;
        }
        
        .status-icon {
            font-size: 18px;
        }
        
        .footer {
            padding: 20px 30px;
            background: #f8f9fa;
            text-align: center;
            font-size: 12px;
            color: #6c757d;
            border-top: 1px solid #e9ecef;
        }
        
        .no-reports {
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }
    """
    
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Сводный отчёт по серверам</title>
    <style>
{css}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Сводный отчёт по серверам</h1>
            <div class="subtitle">Сгенерировано: {generated_at}</div>
        </div>
        
        <div class="summary">
            <div class="summary-card total">
                <div class="number">{total_reports}</div>
                <div class="label">Отчётов</div>
            </div>
            <div class="summary-card errors">
                <div class="number">{servers_with_errors}</div>
                <div class="label">С ошибками</div>
            </div>
            <div class="summary-card warnings">
                <div class="number">{servers_warning}</div>
                <div class="label">С предупреждениями</div>
            </div>
            <div class="summary-card ok">
                <div class="number">{servers_ok}</div>
                <div class="label">OK</div>
            </div>
        </div>
        
        <div class="reports-list">
"""
    
    if not grouped:
        html += """
            <div class="no-reports">
                <p>Нет доступных отчётов</p>
            </div>
"""
    else:
        # Сортируем даты (новые сначала)
        sorted_dates = sorted(grouped.keys(), reverse=True)
        
        for date_str in sorted_dates:
            domains = grouped[date_str]
            
            # Считаем статистику за день
            day_errors = 0
            day_warnings = 0
            day_count = 0
            for domain_reports in domains.values():
                for _, metadata in domain_reports:
                    day_count += 1
                    if metadata:
                        day_errors += metadata.total_errors
                        day_warnings += metadata.total_warnings
            
            html += f"""
            <div class="date-section">
                <div class="date-header" onclick="toggleDate(this)">
                    <span>📅 {date_str} ({day_count} отчётов, {day_errors} ошибок, {day_warnings} предупреждений)</span>
                    <span class="expand-icon">▼</span>
                </div>
                <div class="date-content">
"""
            
            # Сортируем домены
            sorted_domains = sorted(domains.keys())
            
            for domain in sorted_domains:
                domain_reports = domains[domain]
                
                html += f"""
                    <div class="domain-section">
                        <div class="domain-header">
                            <span class="domain-icon">🌐</span>{domain}
                        </div>
                        <div class="server-list">
"""
                
                for file_info, metadata in domain_reports:
                    # Определяем статус и иконку
                    if metadata:
                        if metadata.status == 'error':
                            status_icon = '❌'
                            status_class = 'error'
                            status_text = f'{metadata.total_errors} ошибок'
                        elif metadata.status == 'warning':
                            status_icon = '⚠️'
                            status_class = 'warning'
                            status_text = f'{metadata.total_warnings} предупреждений'
                        elif metadata.status == 'connection_error':
                            status_icon = '🔌'
                            status_class = 'unreachable'
                            status_text = 'Недоступен'
                        else:
                            status_icon = '✅'
                            status_class = 'success'
                            status_text = 'OK'
                    else:
                        status_icon = '❓'
                        status_class = 'unreachable'
                        status_text = 'Неизвестно'
                    
                    html += f"""
                            <div class="server-item">
                                <div class="server-info">
                                    <a href="{file_info.filepath.name}" class="server-name">{file_info.hostname}</a>
                                    <div class="server-time">{file_info.time_str}</div>
                                </div>
                                <div class="server-stats">
                                    <span class="badge {status_class}">{status_text}</span>
                                    <span class="status-icon">{status_icon}</span>
                                </div>
                            </div>
"""
                
                html += """
                        </div>
                    </div>
"""
            
            html += """
                </div>
            </div>
"""
    
    html += f"""
        </div>
        
        <div class="footer">
            Сводный отчёт сгенерирован автоматически • {generated_at}
        </div>
    </div>
    
    <script>
        function toggleDate(header) {{
            header.classList.toggle('collapsed');
            const content = header.nextElementSibling;
            content.classList.toggle('collapsed');
        }}
    </script>
</body>
</html>
"""
    
    return html


def main():
    """Основная функция"""
    args = parse_arguments()
    logger = setup_logging(args.verbose)

    # Загружаем правила группировки
    load_grouping_rules()

    # Собираем список серверов из разных источников
    hostnames = []

    # Добавляем серверы из командной строки
    if args.hostnames:
        hostnames.extend(args.hostnames)

    # Добавляем серверы из файла
    if args.file:
        try:
            file_servers = read_servers_from_file(args.file)
            hostnames.extend(file_servers)
            logger.info(
                f"📄 Загружено {len(file_servers)} серверов из файла: {args.file}"
            )
        except Exception as e:
            logger.error(f"❌ Ошибка при чтении файла серверов: {e}")
            sys.exit(1)

    # Добавляем серверы из SSH конфига
    if args.use_ssh_config:
        try:
            ssh_hosts = read_hosts_from_ssh_config(args.ssh_config)
            hostnames.extend(ssh_hosts)
            config_path = args.ssh_config if args.ssh_config else "~/.ssh/config"
            logger.info(
                f"🔧 Загружено {len(ssh_hosts)} хостов из SSH конфига: {config_path}"
            )
        except Exception as e:
            logger.error(f"❌ Ошибка при чтении SSH конфига: {e}")
            sys.exit(1)

    # Проверяем, что указан хотя бы один сервер
    if not hostnames:
        logger.error("❌ Не указаны серверы для проверки!")
        logger.error("   Используйте: python run.py server1.example.com")
        logger.error("   Или:         python run.py --file servers.txt")
        logger.error("   Или:         python run.py --use-ssh-config")
        sys.exit(1)

    # Удаляем дубликаты, сохраняя порядок
    seen = set()
    unique_hostnames = []
    for hostname in hostnames:
        if hostname not in seen:
            seen.add(hostname)
            unique_hostnames.append(hostname)

    hostnames = unique_hostnames

    # Запрашиваем пароль если нужно
    if args.ask_password:
        try:
            password = getpass.getpass(
                f"🔐 Введите пароль SSH для {args.ssh_user}@servers: "
            )
            if not password:
                logger.error("❌ Пароль не может быть пустым!")
                sys.exit(1)
            # Сохраняем пароль в args для передачи в check_server
            args.password = password
        except KeyboardInterrupt:
            logger.warning("\n⚠️  Отменено пользователем")
            sys.exit(1)
    else:
        args.password = None

    logger.info("=" * 80)
    logger.info(f"🔍 Проверка серверов: {', '.join(hostnames)}")
    logger.info(f"⏱️  Период: последние {args.period} часов")
    logger.info("=" * 80)

    # Проверяем каждый сервер
    reports = []

    for hostname in hostnames:
        try:
            report = check_server(hostname, args)
            reports.append(report)

            # Пропускаем генерацию HTML если используется --ai-output
            if args.ai_output:
                continue

            # Генерируем отчёт для этого сервера
            reports_dir = Path(args.output)
            reports_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
            output_file = str(reports_dir / f"report_{hostname}_{timestamp}.html")

            generate_html_report(report, output_file)
            logger.info(f"✅ Отчёт сохранён: {output_file}")

            # Сохраняем JSON если требуется
            if args.json:
                json_file = output_file.replace(".html", ".json")
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(
                        asdict(report), f, ensure_ascii=False, indent=2, default=str
                    )
                logger.info(f"📄 JSON сохранён: {json_file}")

        except KeyboardInterrupt:
            logger.warning("\n⚠️  Прервано пользователем")
            sys.exit(1)
        except Exception as e:
            logger.error(
                f"❌ Ошибка при проверке {hostname}: {e}", exc_info=args.verbose
            )

    # AI-friendly вывод
    if args.ai_output:
        generator = AIOutputGenerator(reports, args)
        
        if args.ai_format == "compact":
            print(generator.to_compact_json())
        else:
            print(generator.to_json())
        
        # Завершаем работу после AI-вывода
        return

    # Генерируем сводный отчёт index.html
    reports_dir = Path(args.output)
    generate_index_html(reports_dir)

    # Выводим итоговую статистику
    logger.info("=" * 80)
    total_errors = sum(r.total_errors for r in reports)
    total_warnings = sum(r.total_warnings for r in reports)
    logger.info(
        f"📊 Итого: {total_errors} ошибок, {total_warnings} предупреждений на {len(reports)} серверах"
    )
    logger.info("=" * 80)


if __name__ == "__main__":
    main()
