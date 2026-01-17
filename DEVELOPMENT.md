# Разработка и тестирование

## Локальный запуск тестов

```bash
# Установка dev-зависимостей
pip install -r requirements-dev.txt

# Запуск тестов
pytest tests/ -v

# Запуск с покрытием
pytest tests/ --cov=run --cov-report=html
```

## CI/CD

Проект использует GitHub Actions для автоматического тестирования и сборки:

- **[test.yml](.github/workflows/test.yml)** - запускается при каждом push/PR в main
  - Тесты на Python 3.8, 3.11, 3.12
  - Тесты на Linux и Windows
  - Линтинг с flake8
  - Проверка сборки бинарников

- **[release.yml](.github/workflows/release.yml)** - запускается при создании тега `v*`
  - Сначала запускает все тесты
  - Только при успешных тестах собирает бинарники
  - Публикует релиз с бинарниками для Linux и Windows

## Структура тестов

Тесты находятся в директории [`tests/`](tests/):

- `test_run.py` - unit-тесты основных функций
  - Нормализация сообщений
  - Классификация критичности
  - Чтение файлов серверов
  - Группировка записей
  - Валидация файла правил

## Добавление новой проверки (Legacy)

1. Добавьте метод в класс `ServerChecks`:

```python
def check_my_service(self) -> CheckResult:
    result = CheckResult(
        name='my_service',
        source_name='My Service',
        source_path='/var/log/myservice.log',
        errors=0,
        warnings=0,
        status='success'
    )

    try:
        cmd = 'grep ERROR /var/log/myservice.log'
        stdout, stderr, code = self.ssh.execute(cmd)

        # Парсинг вывода и заполнение result

    except Exception as e:
        self.logger.error(f"check_my_service: {e}")
        result.status = 'error'

    return result
```

2. Добавьте метод в список проверок в функции `check_server()`:

```python
check_functions = [
    # ... существующие проверки
    checks.check_my_service,  # Ваша новая проверка
]
```
