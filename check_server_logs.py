#!/usr/bin/env python3
"""
Server Logs Analysis Tool
Подключается к серверам по SSH и анализирует логи за указанный период
"""

import argparse
import logging
import sys
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
import paramiko
from jinja2 import Environment, FileSystemLoader, select_autoescape


# Настройка логирования
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Настройка логирования"""
    level = logging.DEBUG if verbose else logging.INFO
    
    # Логирование в консоль
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    
    # Логирование в файл
    file_handler = logging.FileHandler('check_server_logs.log')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    
    # Настройка root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    # Отключаем verbose логи paramiko
    logging.getLogger('paramiko').setLevel(logging.WARNING)
    
    return logger


# Парсинг аргументов командной строки
def parse_arguments() -> argparse.Namespace:
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description='Анализ логов серверов через SSH',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s srv-hv4
  %(prog)s srv-hv1 srv-hv2 srv-hv4 --period 48
  %(prog)s srv-hv4 --cleanup-threshold 85 --verbose
  %(prog)s srv-hv1 --output custom_report.html
        """
    )
    
    parser.add_argument(
        'hostnames',
        nargs='+',
        help='Один или несколько хостов для проверки'
    )
    
    parser.add_argument(
        '--period',
        type=int,
        default=24,
        help='Период анализа в часах (по умолчанию: 24)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Имя выходного файла (по умолчанию: report_HOSTNAME_YYYY-MM-DD_HH-MM.html)'
    )
    
    parser.add_argument(
        '--cleanup-threshold',
        type=int,
        default=None,
        help='Автоочистка ZFS при превышении N%% (по умолчанию: выключено)'
    )
    
    parser.add_argument(
        '--parallel',
        type=int,
        default=4,
        help='Количество параллельных потоков (по умолчанию: 4)'
    )
    
    parser.add_argument(
        '--ssh-config',
        type=str,
        default=None,
        help='Путь к SSH конфигу (по умолчанию: системные настройки SSH)'
    )
    
    parser.add_argument(
        '--ssh-user',
        type=str,
        default='root',
        help='Пользователь SSH (по умолчанию: root)'
    )
    
    parser.add_argument(
        '--ssh-timeout',
        type=int,
        default=30,
        help='Timeout SSH команд в секундах (по умолчанию: 30)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Подробный вывод в консоль'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Дополнительно сохранить результаты в JSON'
    )
    
    return parser.parse_args()


# Дата-классы для хранения результатов
@dataclass
class LogEntry:
    """Запись лога"""
    timestamp: str
    type: str
    severity: str  # 'critical', 'warning', 'info'
    message: str
    source: str = ''


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
    uptime: str = ''
    load_average: str = ''


class SSHConnection:
    """Управление SSH соединением"""
    
    def __init__(self, hostname: str, username: str = 'root', 
                 ssh_config: Optional[str] = None, timeout: int = 30):
        self.hostname = hostname
        self.username = username
        self.ssh_config = ssh_config
        self.timeout = timeout
        self.client = None
        self.logger = logging.getLogger(f'SSH[{hostname}]')
    
    def connect(self) -> Tuple[bool, Optional[str]]:
        """Подключение к серверу"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.hostname,
                'username': self.username,
                'timeout': self.timeout,
                'look_for_keys': True,
                'allow_agent': True,
            }
            
            # Если указан SSH config, используем его
            if self.ssh_config:
                ssh_config_path = Path(self.ssh_config).expanduser()
                if ssh_config_path.exists():
                    ssh_config_obj = paramiko.SSHConfig()
                    with open(ssh_config_path) as f:
                        ssh_config_obj.parse(f)
                    
                    host_config = ssh_config_obj.lookup(self.hostname)
                    
                    # Применяем настройки из конфига
                    if 'hostname' in host_config:
                        connect_kwargs['hostname'] = host_config['hostname']
                    if 'user' in host_config:
                        connect_kwargs['username'] = host_config['user']
                    if 'port' in host_config:
                        connect_kwargs['port'] = int(host_config['port'])
                    if 'identityfile' in host_config:
                        connect_kwargs['key_filename'] = host_config['identityfile']
            
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
                    command, 
                    timeout=self.timeout
                )
                stdout_text = stdout.read().decode('utf-8', errors='replace')
                stderr_text = stderr.read().decode('utf-8', errors='replace')
                exit_code = stdout.channel.recv_exit_status()
                
                return stdout_text, stderr_text, exit_code
                
            except Exception as e:
                if attempt < retries - 1:
                    self.logger.warning(f"Попытка {attempt + 1}/{retries} не удалась: {e}")
                    continue
                else:
                    self.logger.error(f"Команда не выполнена после {retries} попыток: {e}")
                    return '', str(e), -1
        
        return '', 'Max retries exceeded', -1
    
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
        'degraded', 'unavail', 'failed', 'critical', 'panic',
        'out of memory', 'disk full', 'no space left',
        'cannot allocate', 'segfault', 'kernel panic'
    ]
    
    # Некритические предупреждения
    warning_patterns = [
        'inotify', 'warning', 'deprecated', 'retry',
        'timeout', 'slow', 'high load'
    ]
    
    # Проверяем на критичность
    for pattern in critical_patterns:
        if pattern in message_lower:
            return 'critical'
    
    # Проверяем на предупреждения
    for pattern in warning_patterns:
        if pattern in message_lower:
            return 'warning'
    
    # Специальные правила для конкретных проверок
    if check_name == 'journalctl_errors':
        # termproxy единичные ошибки - не критичны
        if 'termproxy' in message_lower and 'failed: exit code 1' in message_lower:
            return 'warning'
    
    return 'critical'


# Функции проверок
class ServerChecks:
    """Класс с методами проверок сервера"""
    
    def __init__(self, ssh: SSHConnection, period_hours: int):
        self.ssh = ssh
        self.period_hours = period_hours
        self.logger = logging.getLogger(f'Checks[{ssh.hostname}]')
    
    def check_journalctl_errors(self) -> CheckResult:
        """Проверка системного журнала (ошибки)"""
        result = CheckResult(
            name='journalctl_errors',
            source_name='Системный журнал (критические)',
            source_path='journalctl --priority=err',
            errors=0,
            warnings=0,
            status='success'
        )
        
        try:
            cmd = f'journalctl --since "{self.period_hours} hours ago" --priority=err --no-pager'
            stdout, stderr, code = self.ssh.execute(cmd)
            
            if code != 0:
                result.status = 'error'
                return result
            
            lines = [l for l in stdout.strip().split('\n') if l]
            
            for line in lines:
                # Парсим строку journalctl
                match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(.+)', line)
                if match:
                    timestamp, message = match.groups()
                    severity = classify_severity(message, 'journalctl_errors')
                    
                    entry = LogEntry(
                        timestamp=timestamp,
                        type='Error',
                        severity=severity,
                        message=message
                    )
                    result.entries.append(entry)
                    
                    if severity == 'critical':
                        result.errors += 1
                    else:
                        result.warnings += 1
            
            if result.errors > 0:
                result.status = 'error'
            elif result.warnings > 0:
                result.status = 'warning'
                
        except Exception as e:
            self.logger.error(f"check_journalctl_errors: {e}")
            result.status = 'error'
        
        return result
    
    def check_journalctl_warnings(self) -> CheckResult:
        """Проверка системного журнала (предупреждения)"""
        result = CheckResult(
            name='journalctl_warnings',
            source_name='Системный журнал (предупреждения)',
            source_path='journalctl --priority=warning',
            errors=0,
            warnings=0,
            status='success'
        )
        
        try:
            cmd = f'journalctl --since "{self.period_hours} hours ago" --priority=warning --no-pager'
            stdout, stderr, code = self.ssh.execute(cmd)
            
            if code != 0:
                result.status = 'error'
                return result
            
            lines = [l for l in stdout.strip().split('\n') if l]
            
            for line in lines:
                match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(.+)', line)
                if match:
                    timestamp, message = match.groups()
                    
                    entry = LogEntry(
                        timestamp=timestamp,
                        type='Warning',
                        severity='warning',
                        message=message
                    )
                    result.entries.append(entry)
                    result.warnings += 1
            
            if result.warnings > 0:
                result.status = 'warning'
                
        except Exception as e:
            self.logger.error(f"check_journalctl_warnings: {e}")
            result.status = 'error'
        
        return result
    
    def check_auth_log(self) -> CheckResult:
        """Проверка лога аутентификации"""
        result = CheckResult(
            name='auth_log',
            source_name='Лог аутентификации',
            source_path='/var/log/auth.log',
            errors=0,
            warnings=0,
            status='success'
        )
        
        try:
            cmd = f'grep -i fail /var/log/auth.log | tail -20'
            stdout, stderr, code = self.ssh.execute(cmd)
            
            lines = [l for l in stdout.strip().split('\n') if l and 'fail' in l.lower()]
            
            for line in lines:
                # Парсим timestamp из auth.log
                match = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
                timestamp = match.group(1) if match else 'Unknown'
                
                entry = LogEntry(
                    timestamp=timestamp,
                    type='Authentication Failure',
                    severity='warning',
                    message=line
                )
                result.entries.append(entry)
                result.warnings += 1
            
            if result.warnings > 0:
                result.status = 'warning'
                
        except Exception as e:
            self.logger.error(f"check_auth_log: {e}")
            result.status = 'error'
        
        return result
    
    def check_fail2ban(self) -> CheckResult:
        """Проверка Fail2ban"""
        result = CheckResult(
            name='fail2ban',
            source_name='Fail2ban (защита от брутфорса)',
            source_path='/var/log/fail2ban.log',
            errors=0,
            warnings=0,
            status='success'
        )
        
        try:
            cmd = 'cat /var/log/fail2ban.log 2>/dev/null | grep -i found'
            stdout, stderr, code = self.ssh.execute(cmd)
            
            lines = [l for l in stdout.strip().split('\n') if l and 'found' in l.lower()]
            
            for line in lines:
                match = re.match(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
                timestamp = match.group(1) if match else 'Unknown'
                
                entry = LogEntry(
                    timestamp=timestamp,
                    type='Suspicious Activity',
                    severity='info',
                    message=line
                )
                result.entries.append(entry)
                result.warnings += 1
            
            if result.warnings > 0:
                result.status = 'warning'
                
        except Exception as e:
            self.logger.error(f"check_fail2ban: {e}")
            result.status = 'error'
        
        return result
    
    def check_corosync(self) -> CheckResult:
        """Проверка Corosync кластера"""
        result = CheckResult(
            name='corosync',
            source_name='Corosync кластер',
            source_path='journalctl -u corosync',
            errors=0,
            warnings=0,
            status='success'
        )
        
        try:
            cmd = f'journalctl -u corosync --since "{self.period_hours} hours ago" --no-pager | grep -i "no active links\\|link.*down\\|lost quorum"'
            stdout, stderr, code = self.ssh.execute(cmd)
            
            lines = [l for l in stdout.strip().split('\n') if l]
            
            for line in lines:
                match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                timestamp = match.group(1) if match else 'Unknown'
                
                severity = 'critical' if 'lost quorum' in line.lower() else 'warning'
                
                entry = LogEntry(
                    timestamp=timestamp,
                    type='Cluster Issue',
                    severity=severity,
                    message=line
                )
                result.entries.append(entry)
                
                if severity == 'critical':
                    result.errors += 1
                else:
                    result.warnings += 1
            
            if result.errors > 0:
                result.status = 'error'
            elif result.warnings > 0:
                result.status = 'warning'
                
        except Exception as e:
            self.logger.error(f"check_corosync: {e}")
            result.status = 'error'
        
        return result
    
    def check_dmesg(self) -> CheckResult:
        """Проверка системных сообщений ядра"""
        result = CheckResult(
            name='dmesg',
            source_name='Системные сообщения ядра',
            source_path='dmesg',
            errors=0,
            warnings=0,
            status='success'
        )
        
        try:
            cmd = 'dmesg -T --level=err,warn 2>/dev/null | tail -50'
            stdout, stderr, code = self.ssh.execute(cmd)
            
            lines = [l for l in stdout.strip().split('\n') if l]
            
            for line in lines:
                match = re.match(r'\[([^\]]+)\]', line)
                timestamp = match.group(1) if match else 'Unknown'
                
                severity = 'critical' if 'error' in line.lower() else 'warning'
                
                entry = LogEntry(
                    timestamp=timestamp,
                    type='Kernel Message',
                    severity=severity,
                    message=line
                )
                result.entries.append(entry)
                
                if severity == 'critical':
                    result.errors += 1
                else:
                    result.warnings += 1
            
            if result.errors > 0:
                result.status = 'error'
            elif result.warnings > 0:
                result.status = 'warning'
                
        except Exception as e:
            self.logger.error(f"check_dmesg: {e}")
            result.status = 'error'
        
        return result
    
    def check_pveproxy(self) -> CheckResult:
        """Проверка PVE Proxy (HTTP доступ)"""
        result = CheckResult(
            name='pveproxy',
            source_name='PVE Proxy (HTTP доступ)',
            source_path='/var/log/pveproxy/access.log',
            errors=0,
            warnings=0,
            status='success'
        )
        
        try:
            cmd = 'tail -100 /var/log/pveproxy/access.log 2>/dev/null | grep -E " (4[0-9]{2}|5[0-9]{2}) "'
            stdout, stderr, code = self.ssh.execute(cmd)
            
            lines = [l for l in stdout.strip().split('\n') if l]
            
            for line in lines:
                match = re.search(r' (\d{3}) ', line)
                http_code = match.group(1) if match else '000'
                
                severity = 'critical' if http_code.startswith('5') else 'warning'
                
                entry = LogEntry(
                    timestamp='Recent',
                    type=f'HTTP {http_code}',
                    severity=severity,
                    message=line
                )
                result.entries.append(entry)
                
                if severity == 'critical':
                    result.errors += 1
                else:
                    result.warnings += 1
            
            if result.errors > 0:
                result.status = 'error'
            elif result.warnings > 0:
                result.status = 'warning'
                
        except Exception as e:
            self.logger.error(f"check_pveproxy: {e}")
            result.status = 'error'
        
        return result


    
    def check_vms_status(self) -> CheckResult:
        """Проверка статуса виртуальных машин"""
        result = CheckResult(
            name='vms_status',
            source_name='Виртуальные машины (статус)',
            source_path='qm list',
            errors=0,
            warnings=0,
            status='success'
        )
        
        try:
            cmd = 'qm list 2>/dev/null'
            stdout, stderr, code = self.ssh.execute(cmd)
            
            if code != 0:
                result.status = 'error'
                return result
            
            lines = stdout.strip().split('\n')[1:]  # Пропускаем заголовок
            
            stopped_vms = []
            running_vms = []
            
            for line in lines:
                if 'stopped' in line.lower():
                    parts = line.split()
                    vm_id = parts[0] if len(parts) > 0 else 'Unknown'
                    vm_name = parts[1] if len(parts) > 1 else 'Unknown'
                    stopped_vms.append(f"VM {vm_id} ({vm_name})")
                elif 'running' in line.lower():
                    parts = line.split()
                    vm_id = parts[0] if len(parts) > 0 else 'Unknown'
                    vm_name = parts[1] if len(parts) > 1 else 'Unknown'
                    running_vms.append(f"VM {vm_id} ({vm_name})")
            
            if stopped_vms:
                for vm in stopped_vms:
                    entry = LogEntry(
                        timestamp='Current',
                        type='VM Stopped',
                        severity='info',
                        message=f"{vm} находится в состоянии STOPPED"
                    )
                    result.entries.append(entry)
                    result.warnings += 1
                
                result.status = 'warning'
            
            result.details['stopped_vms'] = len(stopped_vms)
            result.details['running_vms'] = len(running_vms)
            result.details['total_vms'] = len(stopped_vms) + len(running_vms)
                
        except Exception as e:
            self.logger.error(f"check_vms_status: {e}")
            result.status = 'error'
        
        return result
    
    def check_storage(self) -> CheckResult:
        """Проверка хранилищ"""
        result = CheckResult(
            name='storage',
            source_name='Хранилища (дисковое пространство)',
            source_path='pvesm status',
            errors=0,
            warnings=0,
            status='success'
        )
        
        try:
            cmd = 'pvesm status 2>/dev/null'
            stdout, stderr, code = self.ssh.execute(cmd)
            
            if code != 0:
                result.status = 'error'
                return result
            
            lines = stdout.strip().split('\n')[1:]  # Пропускаем заголовок
            
            for line in lines:
                parts = line.split()
                if len(parts) < 6:
                    continue
                
                name = parts[0]
                storage_type = parts[1]
                status = parts[2]
                usage_percent = parts[5].rstrip('%')
                
                if status == 'disabled':
                    continue
                
                try:
                    usage = float(usage_percent)
                    
                    if usage > 90:
                        severity = 'critical'
                        result.errors += 1
                        result.status = 'error'
                    elif usage > 75:
                        severity = 'warning'
                        result.warnings += 1
                        if result.status == 'success':
                            result.status = 'warning'
                    else:
                        continue
                    
                    entry = LogEntry(
                        timestamp='Current',
                        type='Storage Usage',
                        severity=severity,
                        message=f"{name} ({storage_type}): {usage}% использовано"
                    )
                    result.entries.append(entry)
                    
                    result.details[name] = {
                        'type': storage_type,
                        'usage': usage,
                        'status': status
                    }
                    
                except ValueError:
                    continue
                
        except Exception as e:
            self.logger.error(f"check_storage: {e}")
            result.status = 'error'
        
        return result
    
    def check_cluster(self) -> CheckResult:
        """Проверка кластера Proxmox"""
        result = CheckResult(
            name='cluster',
            source_name='Кластер Proxmox (кворум)',
            source_path='pvecm status',
            errors=0,
            warnings=0,
            status='success'
        )
        
        try:
            cmd = 'pvecm status 2>/dev/null'
            stdout, stderr, code = self.ssh.execute(cmd)
            
            if code != 0:
                result.status = 'error'
                return result
            
            # Парсим вывод pvecm status
            quorate = 'No'
            expected_votes = 0
            total_votes = 0
            
            for line in stdout.split('\n'):
                if 'Quorate:' in line:
                    quorate = line.split(':')[1].strip()
                elif 'Expected votes:' in line:
                    expected_votes = int(line.split(':')[1].strip())
                elif 'Total votes:' in line:
                    total_votes = int(line.split(':')[1].strip())
            
            if quorate != 'Yes':
                entry = LogEntry(
                    timestamp='Current',
                    type='Cluster Quorum Lost',
                    severity='critical',
                    message=f"Кластер потерял кворум! Expected: {expected_votes}, Total: {total_votes}"
                )
                result.entries.append(entry)
                result.errors += 1
                result.status = 'error'
            else:
                entry = LogEntry(
                    timestamp='Current',
                    type='Cluster OK',
                    severity='info',
                    message=f"Кворум достигнут. Votes: {total_votes}/{expected_votes}"
                )
                result.entries.append(entry)
            
            result.details['quorate'] = quorate
            result.details['expected_votes'] = expected_votes
            result.details['total_votes'] = total_votes
                
        except Exception as e:
            self.logger.error(f"check_cluster: {e}")
            result.status = 'error'
        
        return result
    
    def check_zfs_snapshots(self, cleanup_threshold: Optional[int] = None) -> CheckResult:
        """Проверка ZFS снимков и автоочистка"""
        result = CheckResult(
            name='zfs_snapshots',
            source_name='ZFS снимки',
            source_path='zfs list -t snapshot',
            errors=0,
            warnings=0,
            status='success'
        )
        
        try:
            # Получаем список пулов со статусом
            cmd = 'pvesm status 2>/dev/null | grep zfspool'
            stdout, stderr, code = self.ssh.execute(cmd)
            
            if code != 0:
                return result
            
            pools_to_clean = []
            
            for line in stdout.strip().split('\n'):
                if not line:
                    continue
                
                parts = line.split()
                if len(parts) < 6:
                    continue
                
                pool_name = parts[0]
                usage_percent = parts[5].rstrip('%')
                
                try:
                    usage = float(usage_percent)
                    
                    if cleanup_threshold and usage > cleanup_threshold:
                        pools_to_clean.append((pool_name, usage))
                        
                except ValueError:
                    continue
            
            # Выполняем очистку для каждого пула
            for pool_name, initial_usage in pools_to_clean:
                self.logger.info(f"{pool_name}: {initial_usage}% > {cleanup_threshold}%, запуск очистки...")
                
                cleaned = False
                iterations = 0
                max_iterations = 5
                
                current_usage = initial_usage
                
                while current_usage > cleanup_threshold and iterations < max_iterations:
                    iterations += 1
                    
                    # Удаляем 10 самых больших снимков (исключая replicate)
                    cleanup_cmd = (
                        f'zfs list -t snapshot -o name -s used {pool_name} | '
                        f'tail -n 10 | grep -v replicate | '
                        f'while read -r line; do zfs destroy "$line" 2>/dev/null; done'
                    )
                    
                    stdout, stderr, code = self.ssh.execute(cleanup_cmd)
                    
                    # Проверяем новое использование
                    check_cmd = f'pvesm status 2>/dev/null | grep "^{pool_name} "'
                    stdout, stderr, code = self.ssh.execute(check_cmd)
                    
                    if code == 0 and stdout:
                        parts = stdout.split()
                        if len(parts) >= 6:
                            new_usage_str = parts[5].rstrip('%')
                            try:
                                new_usage = float(new_usage_str)
                                
                                self.logger.info(f"  Итерация {iterations}: {current_usage}% -> {new_usage}%")
                                
                                if new_usage < current_usage:
                                    cleaned = True
                                    current_usage = new_usage
                                else:
                                    break  # Нет смысла продолжать
                                    
                            except ValueError:
                                break
                
                if cleaned:
                    entry = LogEntry(
                        timestamp='Current',
                        type='ZFS Cleanup',
                        severity='info',
                        message=f"{pool_name}: очистка завершена за {iterations} итераций, {initial_usage}% -> {current_usage}%"
                    )
                    result.entries.append(entry)
                    result.warnings += 1
                    result.status = 'warning'
                    
                    result.details[pool_name] = {
                        'initial_usage': initial_usage,
                        'final_usage': current_usage,
                        'iterations': iterations,
                        'freed': initial_usage - current_usage
                    }
                
        except Exception as e:
            self.logger.error(f"check_zfs_snapshots: {e}")
            result.status = 'error'
        
        return result
    
    def get_uptime(self) -> str:
        """Получить uptime сервера"""
        try:
            stdout, stderr, code = self.ssh.execute('uptime -p')
            if code == 0:
                return stdout.strip()
        except:
            pass
        return 'Unknown'
    
    def get_load_average(self) -> str:
        """Получить load average"""
        try:
            stdout, stderr, code = self.ssh.execute('uptime')
            if code == 0:
                match = re.search(r'load average: ([\d\., ]+)', stdout)
                if match:
                    return match.group(1)
        except:
            pass
        return 'Unknown'


def check_server(hostname: str, args: argparse.Namespace) -> ServerReport:
    """Проверка одного сервера"""
    logger = logging.getLogger(f'[{hostname}]')
    logger.info("Начало проверки...")
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Подключаемся к серверу
    ssh = SSHConnection(
        hostname=hostname,
        username=args.ssh_user,
        ssh_config=args.ssh_config,
        timeout=args.ssh_timeout
    )
    
    success, error = ssh.connect()
    
    if not success:
        # Создаём отчёт с ошибкой подключения
        logger.error(f"Не удалось подключиться: {error}")
        return ServerReport(
            hostname=hostname,
            timestamp=timestamp,
            period_hours=args.period,
            connection_error=error,
            checks=[]
        )
    
    # Создаём объект для проверок
    checks = ServerChecks(ssh, args.period)
    
    # Список всех проверок
    check_functions = [
        checks.check_journalctl_errors,
        checks.check_journalctl_warnings,
        checks.check_auth_log,
        checks.check_fail2ban,
        checks.check_corosync,
        checks.check_dmesg,
        checks.check_pveproxy,
        checks.check_vms_status,
        checks.check_storage,
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
        future_to_check = {executor.submit(func): func.__name__ for func in check_functions}
        
        for future in as_completed(future_to_check):
            check_name = future_to_check[future]
            try:
                result = future.result()
                results.append(result)
                
                status_icon = '✓' if result.status == 'success' else '⚠️' if result.status == 'warning' else '✗'
                logger.info(f"  {status_icon} {result.source_name} ({result.errors} ошибок, {result.warnings} предупреждений)")
                
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
    
    logger.info(f"✅ Проверка завершена: {total_errors} ошибок, {total_warnings} предупреждений")
    
    return ServerReport(
        hostname=hostname,
        timestamp=timestamp,
        period_hours=args.period,
        connection_error=None,
        checks=results,
        total_errors=total_errors,
        total_warnings=total_warnings,
        uptime=uptime,
        load_average=load_average
    )


def generate_html_report(report: ServerReport, output_file: str):
    """Генерация HTML отчёта"""
    
    # Определяем директорию шаблонов
    script_dir = Path(__file__).parent
    templates_dir = script_dir / 'templates'
    
    # Если шаблон существует, используем Jinja2
    if (templates_dir / 'report_template.html').exists():
        env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        template = env.get_template('report_template.html')
        html_content = template.render(report=report)
    else:
        # Иначе генерируем HTML напрямую
        html_content = generate_html_inline(report)
    
    # Сохраняем файл
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)


def generate_html_inline(report: ServerReport) -> str:
    """Генерация HTML без шаблона"""
    # Этот метод будет содержать inline HTML как запасной вариант
    # Для экономии места использую упрощённую версию
    
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Отчёт по логам {report.hostname}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        .error {{ color: red; }}
        .warning {{ color: orange; }}
        .success {{ color: green; }}
    </style>
</head>
<body>
    <h1>Отчёт по логам сервера {report.hostname}</h1>
    <p><strong>Время генерации:</strong> {report.timestamp}</p>
    <p><strong>Период анализа:</strong> {report.period_hours} часов</p>
    
    {"<p class='error'><strong>Ошибка подключения:</strong> " + report.connection_error + "</p>" if report.connection_error else ""}
    
    <h2>Сводка</h2>
    <p><strong>Всего ошибок:</strong> <span class='error'>{report.total_errors}</span></p>
    <p><strong>Всего предупреждений:</strong> <span class='warning'>{report.total_warnings}</span></p>
    <p><strong>Uptime:</strong> {report.uptime}</p>
    <p><strong>Load Average:</strong> {report.load_average}</p>
    
    <h2>Детальные результаты</h2>
    <table>
        <thead>
            <tr>
                <th>Источник</th>
                <th>Ошибки</th>
                <th>Предупреждения</th>
                <th>Статус</th>
            </tr>
        </thead>
        <tbody>
"""
    
    for check in report.checks:
        status_class = 'error' if check.status == 'error' else 'warning' if check.status == 'warning' else 'success'
        html += f"""
            <tr>
                <td>{check.source_name}<br><small>{check.source_path}</small></td>
                <td class='error'>{check.errors}</td>
                <td class='warning'>{check.warnings}</td>
                <td class='{status_class}'>{check.status}</td>
            </tr>
"""
        
        if check.entries:
            html += f"""
            <tr>
                <td colspan='4'>
                    <details>
                        <summary>Детали ({len(check.entries)} записей)</summary>
                        <ul>
"""
            for entry in check.entries[:20]:  # Ограничиваем количество
                html += f"<li><strong>{entry.timestamp}</strong> [{entry.severity}] {entry.type}: {entry.message[:200]}</li>\n"
            
            if len(check.entries) > 20:
                html += f"<li>... и ещё {len(check.entries) - 20} записей</li>\n"
            
            html += """
                        </ul>
                    </details>
                </td>
            </tr>
"""
    
    html += """
        </tbody>
    </table>
</body>
</html>
"""
    
    return html


def main():
    """Основная функция"""
    args = parse_arguments()
    logger = setup_logging(args.verbose)
    
    logger.info("=" * 80)
    logger.info(f"🔍 Проверка серверов: {', '.join(args.hostnames)}")
    logger.info(f"⏱️  Период: последние {args.period} часов")
    logger.info("=" * 80)
    
    # Проверяем каждый сервер
    reports = []
    
    for hostname in args.hostnames:
        try:
            report = check_server(hostname, args)
            reports.append(report)
            
            # Генерируем отчёт для этого сервера
            if args.output:
                output_file = args.output
            else:
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
                output_file = f"report_{hostname}_{timestamp}.html"
            
            generate_html_report(report, output_file)
            logger.info(f"✅ Отчёт сохранён: {output_file}")
            
            # Сохраняем JSON если требуется
            if args.json:
                json_file = output_file.replace('.html', '.json')
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump(asdict(report), f, ensure_ascii=False, indent=2, default=str)
                logger.info(f"📄 JSON сохранён: {json_file}")
            
        except KeyboardInterrupt:
            logger.warning("\n⚠️  Прервано пользователем")
            sys.exit(1)
        except Exception as e:
            logger.error(f"❌ Ошибка при проверке {hostname}: {e}", exc_info=args.verbose)
    
    # Выводим итоговую статистику
    logger.info("=" * 80)
    total_errors = sum(r.total_errors for r in reports)
    total_warnings = sum(r.total_warnings for r in reports)
    logger.info(f"📊 Итого: {total_errors} ошибок, {total_warnings} предупреждений на {len(reports)} серверах")
    logger.info("=" * 80)


if __name__ == '__main__':
    main()
