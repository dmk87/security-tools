#!/bin/bash

echo "=================================================================="
echo "   УНИВЕРСАЛЬНАЯ ПРОВЕРКА БЕЗОПАСНОСТИ (UBUNTU / DEBIAN / FASTPANEL)"
echo "=================================================================="

# 1. Определение ОС и ядра
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo -e "\n Система: $PRETTY_NAME | Ядро: $(uname -r) | Хост: $(hostname)"
else
    echo -e "\n Система: Неизвестно | Ядро: $(uname -r)"
fi

# 2. Проверка наличия FASTPANEL и версий её пакетов
echo -e "\n Статус FASTPANEL:"
if dpkg -l 2>/dev/null | grep -q "fastpanel2"; then
    dpkg -l | grep -E "fastpanel2 |fastpanel2-fphp |fastpanel.*php" | awk '{print "  - " $2 ": " $3}'
else
    echo "  - FASTPANEL не установлена на этом сервере."
fi

# Функция сравнения версий dpkg (возвращает 0, если $1 >= $2)
ver_ge() {
    dpkg --compare-versions "$1" ge "$2" 2>/dev/null
}

# Функция проверки версии PHP (с учётом бэкпортов Ubuntu и апстрима)
check_php_status() {
    local BIN="$1"
    local RAW_VER=$("$BIN" -v 2>/dev/null | head -n 1 | awk '{print $2}')
    [ -z "$RAW_VER" ] && return

    # Проверяем, принадлежит ли бинарник системному dpkg-пакету (бэкпорт дистрибутива)
    local PKG_NAME=$(dpkg -S "$BIN" 2>/dev/null | head -n 1 | cut -d: -f1)
    local PKG_VER=""
    if [ -n "$PKG_NAME" ]; then
        PKG_VER=$(dpkg-query -W -f='${Version}' "$PKG_NAME" 2>/dev/null)
    fi

    # 1. Проверка для штатных пакетов Ubuntu (USN-8948-1 закрывает PHP2Shell)
    if [[ "$PKG_VER" == *"ubuntu"* ]]; then
        local USN_OK=0
        if [[ "$PKG_VER" == 8.1.* ]] && ver_ge "$PKG_VER" "8.1.2-1ubuntu2.28"; then USN_OK=1; fi
        if [[ "$PKG_VER" == 8.3.* ]] && ver_ge "$PKG_VER" "8.3.6-0ubuntu0.24.04.13"; then USN_OK=1; fi
        if [[ "$PKG_VER" == 8.5.4* ]] && ver_ge "$PKG_VER" "8.5.4-0ubuntu1.5"; then USN_OK=1; fi
        if [[ "$PKG_VER" == 8.5.9* ]] && ver_ge "$PKG_VER" "8.5.9-0ubuntu2.1"; then USN_OK=1; fi

        if [ "$USN_OK" -eq 1 ]; then
            echo -e "  [БЭКПОРТ UBUNTU] $BIN ($PKG_NAME: $PKG_VER)"
            echo "     -> Октябрьский PHP2Shell закрыт (USN-8948-1). Ожидается бэкпорт Ubuntu для ноябрьских CVE (19.11.2026)."
        else
            echo -e "  [УЯЗВИМ - НУЖЕН APT UPGRADE] $BIN ($PKG_NAME: $PKG_VER)"
            echo "     -> Не установлен даже патч USN-8948-1 (PHP2Shell)! Выполните apt update && apt upgrade."
        fi
        return
    fi

    # 2. Проверка для пакетов FASTPANEL (/opt/php*)
    if [[ "$BIN" == /opt/php* ]] || [[ "$PKG_NAME" == *fastpanel* ]]; then
        echo -e "  [ПАКЕТ FASTPANEL] $BIN -> Версия $RAW_VER ($PKG_NAME: $PKG_VER)"
        echo "     -> Для PHP2Shell патч от 24.10.2026 (8.2.35/8.3.36/8.4.27/8.5.12/7.4.33). Следите за релизом FASTPANEL под 19.11.2026."
        return
    fi

    # 3. Проверка сборок из исходников (/usr/local) и репозитория ondrej/php
    local CLEAN_VER=$(echo "$RAW_VER" | cut -d'-' -f1)
    local NOV_OK=0
    local OCT_OK=0

    if ver_ge "$CLEAN_VER" "8.2.36" && [[ "$CLEAN_VER" == 8.2.* ]]; then NOV_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.3.37" && [[ "$CLEAN_VER" == 8.3.* ]]; then NOV_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.4.28" && [[ "$CLEAN_VER" == 8.4.* ]]; then NOV_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.5.13" && [[ "$CLEAN_VER" == 8.5.* ]]; then NOV_OK=1; fi
    if [[ "$CLEAN_VER" == 8.6.* ]]; then NOV_OK=1; fi

    if ver_ge "$CLEAN_VER" "8.2.35" && [[ "$CLEAN_VER" == 8.2.* ]]; then OCT_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.3.36" && [[ "$CLEAN_VER" == 8.3.* ]]; then OCT_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.4.27" && [[ "$CLEAN_VER" == 8.4.* ]]; then OCT_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.5.12" && [[ "$CLEAN_VER" == 8.5.* ]]; then OCT_OK=1; fi

    if [ "$NOV_OK" -eq 1 ]; then
        echo -e "  [ОК - ПОЛНОСТЬЮ ЗАЩИЩЕН] $BIN -> Версия $RAW_VER (закрыты PHP2Shell и патчи 19.11.2026)"
    elif [ "$OCT_OK" -eq 1 ]; then
        echo -e "  [ВНИМАНИЕ - ТОЛЬКО PHP2SHELL] $BIN -> Версия $RAW_VER"
        echo "     -> Октябрьский PHP2Shell закрыт, но уязвим к патчам от 19.11.2026 (нужны 8.2.36 / 8.3.37 / 8.4.28 / 8.5.13)."
    else
        echo -e "  [КРИТИЧНО - УЯЗВИМ К PHP2SHELL] $BIN -> Версия $RAW_VER!"
        echo "     -> Срочно обновите до 8.2.36 / 8.3.37 / 8.4.28 / 8.5.13!"
    fi
}

# 3. Аудит версий PHP, процессов PHP-FPM и защитных настроек
echo -e "\n Аудит версий PHP и процессов PHP-FPM:"

PHP_BINS=$(find /usr/bin /usr/local/bin /usr/local/sbin /usr/sbin /opt/php* -maxdepth 3 -type f \( -name "php" -o -name "php-fpm*" \) 2>/dev/null | sort -u)

if [ -z "$PHP_BINS" ]; then
    echo "  - Исполняемые файлы PHP на хосте не найдены."
else
    for BIN in $PHP_BINS; do
        check_php_status "$BIN"
        if [[ "$BIN" == */php ]]; then
            UP_PROG=$("$BIN" -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null)
            if [ "$UP_PROG" = "1" ] || [ "${UP_PROG,,}" = "on" ]; then
                echo "     [МИТИГАЦИЯ] Включен session.upload_progress.enabled=On -> задайте =0 в php.ini для защиты от CVE-2026-115560/126714 до выхода патча."
            fi
        fi
    done
fi

# Проверка Nginx на fastcgi_keep_conn (вектор CVE-2026-129289)
if [ -d /etc/nginx ]; then
    KEEP_CONN=$(grep -rn "fastcgi_keep_conn[[:space:]]\+on" /etc/nginx/ 2>/dev/null)
    if [ -n "$KEEP_CONN" ]; then
        echo -e "\n  [МИТИГАЦИЯ CVE-2026-129289] В Nginx найдено 'fastcgi_keep_conn on':"
        echo "$KEEP_CONN" | sed 's/^/     /'
        echo "     -> Если бэкпорт от 19.11.2026 ещё не установлен, отключите fastcgi_keep_conn (или задайте off)."
    fi
fi

# Сверка дат обновления пакетов и старта PHP-FPM (только на хосте, без Docker)
LATEST_PHP_PKG=$(ls -t /var/lib/dpkg/info/*php*.list 2>/dev/null | head -n 1)
PKG_EPOCH=0
if [ -n "$LATEST_PHP_PKG" ]; then
    PKG_EPOCH=$(stat -c %Y "$LATEST_PHP_PKG")
    PKG_DATE=$(date -d "@$PKG_EPOCH" "+%Y-%m-%d %H:%M:%S")
    echo -e "\n  Последнее обновление dpkg-пакетов PHP: $PKG_DATE ($(basename "$LATEST_PHP_PKG" .list))"
fi

PIDS=$(pgrep -f "php-fpm: master process")
if [ -n "$PIDS" ]; then
    for PID in $PIDS; do
        if grep -qaE "docker|containerd|kubepods|lxc" "/proc/$PID/cgroup" 2>/dev/null; then
            continue
        fi
        PROC_EPOCH=$(stat -c %Y "/proc/$PID" 2>/dev/null)
        PROC_DATE=$(date -d "@$PROC_EPOCH" "+%Y-%m-%d %H:%M:%S")
        PROC_CMD=$(tr '\0' ' ' < "/proc/$PID/cmdline" | xargs)
        
        if [ "$PKG_EPOCH" -gt "$PROC_EPOCH" ]; then
            echo -e "  [ОПАСНО - НУЖЕН РЕСТАРТ] PHP-FPM (PID $PID) запущен $PROC_DATE (ДО обновления пакетов!)"
            echo "     Команда: $PROC_CMD"
        else
            echo -e "  [ОК] PHP-FPM (PID $PID) запущен: $PROC_DATE"
            echo "     Команда: $PROC_CMD"
        fi
    done
fi

# 4. Проверка доступных обновлений безопасности ОС
echo -e "\n Ожидающие обновления безопасности ОС:"
if grep -qiE "ubuntu|debian" /etc/os-release 2>/dev/null; then
    SEC_UPDATES=$(apt-get -s dist-upgrade 2>/dev/null | grep "^Inst" | grep -i "security" | awk '{print $2}')
    if [ -z "$SEC_UPDATES" ]; then
        echo "  - Ожидающих обновлений безопасности ОС нет."
    else
        echo "  [ВНИМАНИЕ] Требуют установки:"
        echo "$SEC_UPDATES" | sed 's/^/    * /'
    fi
fi

# 5. Поиск подозрительных процессов (исключая Docker/LXC)
echo -e "\n Поиск подозрительных процессов на хосте (в /tmp и /dev/shm):"
FOUND_SUSP=0
while read -r USER PID CPU MEM VSZ RSS TTY STAT START TIME CMD; do
    if echo "$CMD" | grep -qE "/tmp/|/dev/shm/"; then
        if grep -qaE "docker|containerd|kubepods|lxc" "/proc/$PID/cgroup" 2>/dev/null; then
            continue
        fi
        if [ "$FOUND_SUSP" -eq 0 ]; then
            echo "  [ТРЕВОГА] Найдены процессы во временных директориях на хосте:"
            FOUND_SUSP=1
        fi
        echo "  $USER $PID $START $CMD"
    fi
done < <(ps aux --no-headers)

if [ "$FOUND_SUSP" -eq 0 ]; then
    echo "  - Подозрительных процессов на хосте не найдено (контейнеры отфильтрованы)."
fi

# 6. Проверка подозрительных задач в cron у веб-пользователей
echo -e "\n Проверка задач cron у веб-пользователей:"
CRON_FOUND=0
for WEB_USER in www-data apache nginx; do
    if id "$WEB_USER" &>/dev/null; then
        CRON_OUT=$(crontab -u "$WEB_USER" -l 2>/dev/null | grep -v "^#" | grep -v "^$")
        if [ -n "$CRON_OUT" ]; then
            echo "  [ТРЕВОГА] Найдены задачи cron для $WEB_USER:"
            echo "$CRON_OUT" | sed 's/^/    /'
            CRON_FOUND=1
        fi
    fi
done
if [ "$CRON_FOUND" -eq 0 ]; then
    echo "  - Подозрительных задач cron у веб-пользователей не обнаружено."
fi

echo -e "\n=================================================================="
