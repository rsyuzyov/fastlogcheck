# Fast log check tool

Инструмент для быстрой параллельной проверки логов на множестве linux-серверов.  
Пробегается по списку серверов и сорбирает ошибки из логов и создает html-отчет.

<a href="https://htmlpreview.github.io/?https://github.com/rsyuzyov/fastlogcheck/blob/main/docs/example-report.html"><img src="docs/screenshot-example.gif" alt="Пример отчета" width="40%"></a>

## Установка

**Linux:**

```bash
./install.sh
```

**Windows:**

```cmd
install.bat
```

или

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

# Использование

**Linux:**

```bash
python3 ./check_server_logs.py server1.example.com server2.example.com
```

**Windows:**

```powershell
python .\check_server_logs.py server1.example.com server2.example.com
```

📚 **Подробности см. в [USAGE.md](USAGE.md)**

## Проверяемые источники логов

Инструмент проверяет следующие источники логов на каждом сервере:

1. **Системный журнал (критические)** - `journalctl --priority=err`
2. **Системный журнал (предупреждения)** - `journalctl --priority=warning`
3. **Лог аутентификации** - `/var/log/auth.log`
4. **Системные сообщения ядра** - `dmesg`
5. **Fail2ban (защита от брутфорса)** - `/var/log/fail2ban.log`
6. **Corosync кластер** - `journalctl -u corosync`
7. **PVE Proxy (HTTP доступ)** - `/var/log/pveproxy/access.log`
8. **Виртуальные машины (статус)** - `qm list`
9. **Хранилища (дисковое пространство)** - `pvesm status`
10. **Кластер Proxmox (кворум)** - `pvecm status`
11. **ZFS снимки** (опционально с автоочисткой) - `zfs list -t snapshot`
