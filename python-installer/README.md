# Python Auto-Installer для Windows

Скрипт для автоматической установки Python на Windows.

## Использование

```cmd
install-python.bat [/mode=user|system]
```

### Настройки вызова установщика Python

Скрипт использует следующие параметры при вызове официального установщика Python:

```
/quiet                  - Тихая установка без GUI
InstallAllUsers=0/1     - 0 = текущий пользователь, 1 = все пользователи
PrependPath=1           - Добавление Python в PATH
Include_test=0          - Не устанавливать тестовые модули (~5-10 МБ экономии)
Include_launcher=1      - Установить Python Launcher (py.exe)
SimpleInstall=1         - Упрощенная установка (только необходимые компоненты)
```

### Коды возврата

- Exit code `0` - Успешная установка
- Exit code `1` - Ошибка или отмена пользователем
