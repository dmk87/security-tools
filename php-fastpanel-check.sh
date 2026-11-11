#!/bin/bash

echo "=================================================================="
echo "   УНИВЕРСАЛЬНАЯ ПРОВЕРКА БЕЗОПАСНОСТИ (UBUNTU / DEBIAN / FASTPANEL)"
echo "=================================================================="

# 1. Определение ОС и ядра
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo -e "\n[1] Система: $PRETTY_NAME | Ядро: $(uname -r) | Хост: $(hostname)"
else
    echo -e "\n[1] Система: Неизвестно | Ядро: $(uname -r)"
fi

# 2. Проверка наличия FASTPANEL
echo -e "\n[2] Статус FASTPANEL:"
if dpkg -l | grep -q "fastpanel2"; then
    dpkg -l | grep -E "fastpanel2 |fastpanel2-fphp " | awk '{print "  - " $2 ": " $3}'
else
    echo "  - FASTPANEL не установлена на этом сервере."
fi

# 3. Сверка дат обновления пакетов PHP и старта процессов PHP-FPM
echo -e "\n[3] Аудит всех версий PHP (критично для уязвимостей PHP2Shell):"

# Находим дату последнего обновления любых PHP-пакетов (системных или FASTPANEL)
LATEST_PHP_PKG=$(ls -t /var/lib/dpkg/info/*php*.list 2>/dev/null | head -n 1)

if [ -n "$LATEST_PHP_PKG" ]; then
    PKG_EPOCH=$(stat -c %Y "$LATEST_PHP_PKG")
    PKG_DATE=$(date -d "@$PKG_EPOCH" "+%Y-%m-%d %H:%M:%S")
    echo "  Последнее обновление пакетов PHP на диске: $PKG_DATE ($(basename "$LATEST_PHP_PKG" .list))"
else
    PKG_EPOCH=0
    echo "  Пакеты PHP через dpkg не найдены."
fi

# Проверяем все запущенные мастер-процессы php-fpm
PIDS=$(pgrep -f "php-fpm: master process")
if [ -z "$PIDS" ]; then
    echo "  - Активные процессы PHP-FPM не найдены."
else
    for PID in $PIDS; do
        PROC_EPOCH=$(stat -c %Y "/proc/$PID" 2>/dev/null)
        PROC_DATE=$(date -d "@$PROC_EPOCH" "+%Y-%m-%d %H:%M:%S")
        PROC_CMD=$(tr '\0' ' ' < "/proc/$PID/cmdline" | xargs)
        
        if [ "$PKG_EPOCH" -gt "$PROC_EPOCH" ]; then
            echo -e "  [ОПАСНО - НУЖЕН РЕСТАРТ] Процесс запущен: $PROC_DATE (ДО обновления пакетов!)"
            echo "     Путь: $PROC_CMD"
        else
            echo -e "  [ОК] Процесс запущен: $PROC_DATE (после обновления)"
            echo "     Путь: $PROC_CMD"
        fi
    done
fi

# 4. Проверка доступных обновлений безопасности ОС
echo -e "\n[4] Ожидающие обновления безопасности ОС:"
if grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
    SEC_UPDATES=$(apt-get -s dist-upgrade 2>/dev/null | grep "^Inst" | grep -i "security" | awk '{print $2}')
    if [ -z "$SEC_UPDATES" ]; then
        echo "  - Стандартных обновлений безопасности Ubuntu нет."
    else
        echo "  [ВНИМАНИЕ] Требуют установки (стандартный репозиторий):"
        echo "$SEC_UPDATES" | sed 's/^/    * /'
    fi
    if command -v pro &> /dev/null; then
        ESM_COUNT=$(pro security-status --format json 2>/dev/null | grep -o '"esm-apps"' | wc -l)
        echo "  - Статус Ubuntu Pro / ESM: для деталей выполните 'pro security-status --esm-apps'"
    fi
elif grep -qi "debian" /etc/os-release 2>/dev/null; then
    SEC_UPDATES=$(apt-get -s dist-upgrade 2>/dev/null | grep "^Inst" | grep -i "security" | awk '{print $2}')
    if [ -z "$SEC_UPDATES" ]; then
        echo "  - Ожидающих обновлений безопасности Debian нет."
    else
        echo "  [ВНИМАНИЕ] Требуют установки (Debian Security):"
        echo "$SEC_UPDATES" | sed 's/^/    * /'
    fi
fi

# 5. Проверка на базовые признаки компрометации
echo -e "\n[5] Поиск подозрительных процессов в /tmp и /dev/shm:"
SUSP=$(ps aux | grep -E "/tmp/|/dev/shm/" | grep -v grep)
if [ -z "$SUSP" ]; then
    echo "  - Подозрительных процессов не найдено."
else
    echo "  [ТРЕВОГА] Найдены процессы во временных директориях:"
    echo "$SUSP"
fi

echo -e "\n=================================================================="
