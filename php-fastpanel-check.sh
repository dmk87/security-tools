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

# 3. Аудит версий PHP, процессов PHP-FPM и условий эксплуатации уязвимостей (19.11.2026)
echo -e "\n Аудит версий PHP и условий уязвимостей (PHP2Shell / PHPAfterShell / CVE-2026-129289):"

PHP_BINS=$(find /usr/bin /usr/local/bin /usr/local/sbin /usr/sbin /opt/php* -maxdepth 3 -type f \( -name "php" -o -name "php-fpm*" \) 2>/dev/null | sort -u)

if [ -z "$PHP_BINS" ]; then
    echo "  - Исполняемые файлы PHP на хосте не найдены."
else
    for BIN in $PHP_BINS; do
        check_php_status "$BIN"
        
                # Проверяем параметры конфигурации для любого бинарника (и php, и php-fpm)
        if [[ "$BIN" == */php ]] || [[ "$BIN" == */php-fpm* ]]; then
            INI_DUMP=$("$BIN" -i 2>/dev/null)
            UP_PROG=$(echo "$INI_DUMP" | awk -F' => ' '/^session\.upload_progress\.enabled/ {print $2; exit}')
            SAVE_HANDLER=$(echo "$INI_DUMP" | awk -F' => ' '/^session\.save_handler/ {print $2; exit}')
            SER_HANDLER=$(echo "$INI_DUMP" | awk -F' => ' '/^session\.serialize_handler/ {print $2; exit}')
            LOG_ERRORS=$(echo "$INI_DUMP" | awk -F' => ' '/^log_errors/ {print $2; exit}')
            ERROR_LOG=$(echo "$INI_DUMP" | awk -F' => ' '/^error_log/ {print $2; exit}')

            # Условие 1: session.upload_progress.enabled (CVE-2026-115560 и вектор CVE-2026-126714)
            if [ "$UP_PROG" = "1" ] || [ "${UP_PROG,,}" = "on" ]; then
                echo "     [УСЛОВИЕ CVE-2026-115560/126714] Включен session.upload_progress.enabled=On -> задайте =0."
            fi

            # Условие 2: Файловые сессии (обязательное условие для PHPAfterShell / CVE-2026-126714)
            if [ "$SAVE_HANDLER" = "files" ]; then
                echo "     [УСЛОВИЕ PHPAfterShell / CVE-2026-126714] session.save_handler=files -> риск перезаписи сессий (Redis/Memcached не затронуты)."
            fi

            # Условие 3: Нестандартный сериализатор (CVE-2026-115560)
            if [ -n "$SER_HANDLER" ] && [ "$SER_HANDLER" != "php" ]; then
                echo "     [УСЛОВИЕ CVE-2026-115560] Нестандартный session.serialize_handler='$SER_HANDLER'."
            fi

            # Условие 4: Логирование в файл (CVE-2026-129496 - UAF в timezone cache)
            if { [ "$LOG_ERRORS" = "1" ] || [ "${LOG_ERRORS,,}" = "on" ]; } && [ -n "$ERROR_LOG" ] && [ "$ERROR_LOG" != "no value" ] && [ "$ERROR_LOG" != "syslog" ]; then
                echo "     [УСЛОВИЕ CVE-2026-129496] Включено файловое логирование (error_log=$ERROR_LOG) -> риск UAF в timezone cache."
            fi
        fi

    done
fi

# Проверка веб-серверов на удержание соединений с PHP-FPM (вектор CVE-2026-129289 Request Smuggling)
if [ -d /etc/nginx ]; then
    KEEP_CONN=$(grep -rn "fastcgi_keep_conn[[:space:]]\+on" /etc/nginx/ 2>/dev/null)
    if [ -n "$KEEP_CONN" ]; then
        echo -e "\n  [УСЛОВИЕ CVE-2026-129289] В Nginx найдено 'fastcgi_keep_conn on':"
        echo "$KEEP_CONN" | sed 's/^/     /'
        echo "     -> Отключите fastcgi_keep_conn (задайте off), если патч от 19.11.2026 ещё не установлен."
    fi
fi

for APACHE_DIR in /etc/apache2 /etc/httpd; do
    if [ -d "$APACHE_DIR" ]; then
        APACHE_REUSE=$(grep -rni "enablereuse=on" "$APACHE_DIR" 2>/dev/null)
        if [ -n "$APACHE_REUSE" ]; then
            echo -e "\n  [УСЛОВИЕ CVE-2026-129289] В Apache найдено 'enablereuse=on':"
            echo "$APACHE_REUSE" | sed 's/^/     /'
            echo "     -> Отключите enablereuse (задайте enablereuse=off) для защиты от FastCGI Request Smuggling."
        fi
    fi
done

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
