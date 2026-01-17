# Fast log check tool

Инструмент для быстрой проверки логов на linux-серверах.  
Пробегается по списку серверов, собирает ошибки из логов и создает html-отчет.  
Каждый раздел в отчете можно [развернуть до детальных записей](https://htmlpreview.github.io/?https://github.com/rsyuzyov/fastlogcheck/blob/main/docs/example-report.html)  
<a href="https://htmlpreview.github.io/?https://github.com/rsyuzyov/fastlogcheck/blob/main/docs/example-report.html"><img src="docs/screenshot-example.gif" alt="Пример отчета" width="40%"></a>

## Установка

### Готовые бинарники (рекомендуется)

Скачайте готовый бинарник для вашей ОС со страницы [Releases](https://github.com/rsyuzyov/fastlogcheck/releases):

- **Linux:** `fast-log-check-linux-amd64`
- **Windows:** `fast-log-check-windows-amd64.exe`

```bash
# Linux - сделать исполняемым и запустить
chmod +x fast-log-check-linux-amd64
./fast-log-check-linux-amd64 server1.example.com
```

```powershell
# Windows
.\fast-log-check-windows-amd64.exe server1.example.com
```

### Из исходников (требуется Python 3.8+)

**Linux:** `./install.sh`

**Windows:** `install.bat`

## Использование

Можно комбинировать указание серверов в командной строке и файле.  
Для авторизации по паролю используется флаг `--ask-password`.  
Все примеры для windows, линуксоиды и так все знают.

```powershell
python .\run.py server1.example.com server2.example.com
python .\run.py --file servers.txt
python .\run.py server1.example.com --file servers.txt --ask-password
```

**Подробности см. в [USAGE.md](USAGE.md)**

## Проверяемые источники логов

Инструмент проверяет следующие источники логов на каждом сервере:

### Общие проверки

1. **Системный журнал (критические)** - `journalctl --priority=err`
2. **Системный журнал (предупреждения)** - `journalctl --priority=warning`
3. **Лог аутентификации** - `/var/log/auth.log`
4. **Системные сообщения ядра** - `dmesg`
5. **Fail2ban (защита от брутфорса)** - `/var/log/fail2ban.log`
6. **Дисковое пространство** - `df -h`
7. **ZFS снимки** (опционально с автоочисткой) - `zfs list -t snapshot`

### Proxmox

8. **Corosync кластер** - `journalctl -u corosync`
9. **PVE Proxy (HTTP доступ)** - `/var/log/pveproxy/access.log`
10. **Виртуальные машины (статус)** - `qm list`
11. **Кластер Proxmox (кворум)** - `pvecm status`

## Группировка событий

Инструмент автоматически группирует похожие события в логах для улучшения читаемости отчетов. Правила группировки определены в файле [`grouping_rules.json`](grouping_rules.json).

### Структура правил группировки

Каждое правило представляет собой пару "регулярное*выражение" : "параметры*группы", где:

- **Ключ** - регулярное выражение для поиска события в тексте лога
- **title** - человекочитаемое название группы для отображения в отчете
- **severity** - уровень важности события:
  - `error` - критические ошибки (красный цвет в отчете)
  - `warning` - предупреждения (желтый цвет в отчете)
  - `skip` - события, которые следует игнорировать и не включать в отчет

### Настройка группировки

Для добавления новых правил группировки:

1. Откройте файл `grouping_rules.json`
2. Добавьте новое правило в формате:
   ```json
   "регулярное_выражение_для_поиска": {
       "title": "Название группы",
       "severity": "error|warning|skip"
   }
   ```
3. Сохраните файл - изменения вступят в силу при следующем запуске проверки

События, не попадающие ни под одно правило, будут отображаться в отчете как отдельные несгруппированные записи.
