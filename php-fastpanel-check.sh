#!/bin/bash
# Универсальная проверка безопасности (Ubuntu / Debian / FASTPANEL)
# Коды выхода: 0 - чисто, 1 - только предупреждения/инфо, 2 - критичные находки, 3 - зарезервирован под внутреннюю ошибку

CRIT_HITS=0
WARN_HITS=0

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

# Вычисляет статус апстрим-версии PHP; выводит "NOV_OK OCT_OK"
# NOV = закрыты и PHP2Shell, и патчи 19.11.2026; OCT = закрыт только PHP2Shell (патч 24.10.2026)
eval_series() {
    local CLEAN_VER="$1" NOV_OK=0 OCT_OK=0
    if ver_ge "$CLEAN_VER" "8.2.36" && [[ "$CLEAN_VER" == 8.2.* ]]; then NOV_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.3.37" && [[ "$CLEAN_VER" == 8.3.* ]]; then NOV_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.4.28" && [[ "$CLEAN_VER" == 8.4.* ]]; then NOV_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.5.13" && [[ "$CLEAN_VER" == 8.5.* ]]; then NOV_OK=1; fi
    # Всё новее 8.6.0 (включая будущие 8.x и 9.x) новее последнего известного порога патчей
    if ver_ge "$CLEAN_VER" "8.6.0"; then NOV_OK=1; fi

    if ver_ge "$CLEAN_VER" "8.2.35" && [[ "$CLEAN_VER" == 8.2.* ]]; then OCT_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.3.36" && [[ "$CLEAN_VER" == 8.3.* ]]; then OCT_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.4.27" && [[ "$CLEAN_VER" == 8.4.* ]]; then OCT_OK=1; fi
    if ver_ge "$CLEAN_VER" "8.5.12" && [[ "$CLEAN_VER" == 8.5.* ]]; then OCT_OK=1; fi
    # Для 7.4 известен только октябрьский порог; статус ноябрьских патчей неизвестен
    if ver_ge "$CLEAN_VER" "7.4.33" && [[ "$CLEAN_VER" == 7.4.* ]]; then OCT_OK=1; fi

    echo "$NOV_OK $OCT_OK"
}

# Функция проверки версии PHP (с учётом бэкпортов Ubuntu/Debian, sury и апстрима)
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

    # Пакеты ondrej/php (sury) несут апстрим-номера версий: обрабатываем как сборку из репозитория
    if [[ "$PKG_VER" == *sury* ]]; then
        PKG_VER=""
        PKG_NAME=""
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
            WARN_HITS=$((WARN_HITS+1))
        else
            echo -e "  [УЯЗВИМ - НУЖЕН APT UPGRADE] $BIN ($PKG_NAME: $PKG_VER)"
            echo "     -> Не установлен даже патч USN-8948-1 (PHP2Shell)! Выполните apt update && apt upgrade."
            CRIT_HITS=$((CRIT_HITS+1))
        fi
        return
    fi

    # 1b. Штатные пакеты Debian: номер версии может не отражать апстрим-патч (бэкпорт фикса без смены X.Y.Z)
    if [[ "$PKG_VER" == *deb* ]]; then
        echo -e "  [ПАКЕТ DEBIAN] $BIN ($PKG_NAME: $PKG_VER)"
        echo "     -> Debian бэкпортит фиксы без смены апстрим-версии. Сверьте статус вручную с DSA (debian.org/security)."
        WARN_HITS=$((WARN_HITS+1))
        return
    fi

    # 2. Пакеты FASTPANEL (/opt/php*, /opt/fphp): апстрим-версии, проверяем теми же порогами
    if [[ "$BIN" == /opt/php* ]] || [[ "$BIN" == /opt/fphp* ]] || [[ "$PKG_NAME" == *fastpanel* ]]; then
        local CLEAN_VER=$(echo "$RAW_VER" | cut -d'-' -f1)
        local NOV_OK=0 OCT_OK=0
        read -r NOV_OK OCT_OK <<< "$(eval_series "$CLEAN_VER")"

        if [ "$NOV_OK" -eq 1 ]; then
            echo -e "  [ОК - ПОЛНОСТЬЮ ЗАЩИЩЕН] $BIN -> Версия $RAW_VER (закрыты PHP2Shell и патчи 19.11.2026)"
        elif [ "$OCT_OK" -eq 1 ]; then
            echo -e "  [ВНИМАНИЕ - ТОЛЬКО PHP2SHELL] $BIN -> Версия $RAW_VER"
            echo "     -> Октябрьский патч (24.10.2026) есть, ноябрьские (19.11.2026) по номеру версии не подтверждены."
            echo "     -> Если релиз FASTPANEL содержит бэкпорт фиксов без смены версии - сверьте changelog; иначе обновите до 8.2.36/8.3.37/8.4.28/8.5.13."
            WARN_HITS=$((WARN_HITS+1))
        else
            echo -e "  [КРИТИЧНО - УЯЗВИМ К PHP2SHELL] $BIN -> Версия $RAW_VER!"
            echo "     -> Обновите PHP через FASTPANEL (цель: 8.2.36 / 8.3.37 / 8.4.28 / 8.5.13 / 7.4.33)."
            CRIT_HITS=$((CRIT_HITS+1))
        fi
        return
    fi

    # 3. Проверка сборок из исходников (/usr/local) и репозитория ondrej/php (sury)
    local CLEAN_VER=$(echo "$RAW_VER" | cut -d'-' -f1)
    local NOV_OK=0 OCT_OK=0
    read -r NOV_OK OCT_OK <<< "$(eval_series "$CLEAN_VER")"

    if [ "$NOV_OK" -eq 1 ]; then
        echo -e "  [ОК - ПОЛНОСТЬЮ ЗАЩИЩЕН] $BIN -> Версия $RAW_VER (закрыты PHP2Shell и патчи 19.11.2026)"
    elif [ "$OCT_OK" -eq 1 ]; then
        echo -e "  [ВНИМАНИЕ - ТОЛЬКО PHP2SHELL] $BIN -> Версия $RAW_VER"
        echo "     -> Октябрьский PHP2Shell закрыт, но уязвим к патчам от 19.11.2026 (нужны 8.2.36 / 8.3.37 / 8.4.28 / 8.5.13)."
        WARN_HITS=$((WARN_HITS+1))
    else
        echo -e "  [КРИТИЧНО - УЯЗВИМ К PHP2SHELL] $BIN -> Версия $RAW_VER!"
        echo "     -> Срочно обновите до 8.2.36 / 8.3.37 / 8.4.28 / 8.5.13!"
        CRIT_HITS=$((CRIT_HITS+1))
    fi
}

# 3. Аудит версий PHP, процессов PHP-FPM и условий эксплуатации уязвимостей (19.11.2026)
echo -e "\n Аудит версий PHP и условий уязвимостей (PHP2Shell / PHPAfterShell / CVE-2026-129289):"

PHP_BINS=$(find /usr/bin /usr/local/bin /usr/local/sbin /usr/sbin /opt/php* /opt/fphp -maxdepth 3 -type f \( -name "php" -o -name "php-fpm*" \) 2>/dev/null | sort -u)

if [ -z "$PHP_BINS" ]; then
    echo "  - Исполняемые файлы PHP на хосте не найдены."
else
    for BIN in $PHP_BINS; do
        check_php_status "$BIN"

        # Параметры сессий и upload_progress критичны только для веб-SAPI (php-fpm / mod_php / cgi), не для CLI
        if [[ "$BIN" == */php-fpm* ]]; then
            INI_FILE=$("$BIN" -i 2>/dev/null | grep -oE '/[^ "<]+php\.ini' | head -n 1)

            if [ -n "$INI_FILE" ] && [ -f "$INI_FILE" ]; then
                get_ini_val() {
                    grep -E "^[[:space:]]*$1[[:space:]]*=" "$INI_FILE" | tail -n 1 | cut -d'=' -f2- | cut -d';' -f1 | tr -d ' "'
                }
                UP_PROG=$(get_ini_val "session\.upload_progress\.enabled")
                [ -z "$UP_PROG" ] && UP_PROG="1"

                SAVE_HANDLER=$(get_ini_val "session\.save_handler")
                [ -z "$SAVE_HANDLER" ] && SAVE_HANDLER="files"

                SER_HANDLER=$(get_ini_val "session\.serialize_handler")
                [ -z "$SER_HANDLER" ] && SER_HANDLER="php"

                LOG_ERRORS=$(get_ini_val "log_errors")
                [ -z "$LOG_ERRORS" ] && LOG_ERRORS="1"

                ERROR_LOG=$(get_ini_val "error_log")
            else
                UP_PROG="1"
                SAVE_HANDLER="files"
                SER_HANDLER="php"
                LOG_ERRORS="1"
                ERROR_LOG=""
                echo "     -> php.ini для $BIN не определён, проверяю по значениям по умолчанию PHP (upload_progress=On)."
                WARN_HITS=$((WARN_HITS+1))
            fi

            # Условие 1: session.upload_progress.enabled
            if [ "$UP_PROG" = "1" ] || [ "${UP_PROG,,}" = "on" ]; then
                echo "     [УСЛОВИЕ CVE-2026-115560/126714] Включен session.upload_progress.enabled=On -> задайте =0 (${INI_FILE:-default})."
                CRIT_HITS=$((CRIT_HITS+1))
            fi

            # Условие 2: Файловые сессии (PHPAfterShell / CVE-2026-126714) — справочно, дефолт PHP
            if [ "$SAVE_HANDLER" = "files" ]; then
                echo "     [ИНФО PHPAfterShell / CVE-2026-126714] session.save_handler=files — дефолт PHP; сам по себе риска нет, но это необходимая часть цепочки перезаписи сессий при включенном upload_progress (${INI_FILE:-default})."
            fi

            # Условие 3: Нестандартный сериализатор (CVE-2026-115560)
            if [ -n "$SER_HANDLER" ] && [ "$SER_HANDLER" != "php" ]; then
                echo "     [УСЛОВИЕ CVE-2026-115560] Нестандартный session.serialize_handler='$SER_HANDLER'."
                CRIT_HITS=$((CRIT_HITS+1))
            fi

            # Условие 4: Логирование в файл (CVE-2026-129496) — справочно, нормальная практика для FASTPANEL
            if { [ "$LOG_ERRORS" = "1" ] || [ "${LOG_ERRORS,,}" = "on" ]; } && [ -n "$ERROR_LOG" ] && [ "$ERROR_LOG" != "syslog" ]; then
                echo "     [ИНФО CVE-2026-129496] Включено файловое логирование (error_log=$ERROR_LOG)."
            fi
        fi
    done
fi

# Проверка глобальных php.ini для mod_php (Apache) и CGI, если они есть
for WEB_INI in /etc/php/*/apache2/php.ini /etc/php/*/cgi/php.ini; do
    [ -f "$WEB_INI" ] || continue
    WEB_UP=$(grep -E "^[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=" "$WEB_INI" | tail -n 1 | cut -d'=' -f2- | cut -d';' -f1 | tr -d ' "')
    [ -z "$WEB_UP" ] && WEB_UP="1"
    WEB_SAVE=$(grep -E "^[[:space:]]*session\.save_handler[[:space:]]*=" "$WEB_INI" | tail -n 1 | cut -d'=' -f2- | cut -d';' -f1 | tr -d ' "')
    [ -z "$WEB_SAVE" ] && WEB_SAVE="files"
    WEB_SER=$(grep -E "^[[:space:]]*session\.serialize_handler[[:space:]]*=" "$WEB_INI" | tail -n 1 | cut -d'=' -f2- | cut -d';' -f1 | tr -d ' "')
    [ -z "$WEB_SER" ] && WEB_SER="php"

    if [ "$WEB_UP" = "1" ] || [ "${WEB_UP,,}" = "on" ]; then
        echo "     [УСЛОВИЕ CVE-2026-115560/126714] Включен session.upload_progress.enabled=On в $WEB_INI -> задайте =0."
        CRIT_HITS=$((CRIT_HITS+1))
    fi
    if [ "$WEB_SAVE" = "files" ]; then
        echo "     [ИНФО PHPAfterShell] save_handler=files в $WEB_INI (дефолт; смотри условие 1)."
    fi
    if [ "$WEB_SER" != "php" ]; then
        echo "     [УСЛОВИЕ CVE-2026-115560] Нестандартный session.serialize_handler='$WEB_SER' в $WEB_INI."
        CRIT_HITS=$((CRIT_HITS+1))
    fi
done

# Переопределения в conf.d для mod_php/CGI (читаются ПОСЛЕ основного php.ini)
for WEB_INI in /etc/php/*/apache2/conf.d/*.ini /etc/php/*/cgi/conf.d/*.ini; do
    [ -f "$WEB_INI" ] || continue
    WEB_UP=$(grep -E "^[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=" "$WEB_INI" | tail -n 1 | cut -d'=' -f2- | cut -d';' -f1 | tr -d ' "')
    if [ -n "$WEB_UP" ] && { [ "$WEB_UP" = "1" ] || [ "${WEB_UP,,}" = "on" ]; }; then
        echo "     [УСЛОВИЕ CVE-2026-115560/126714] Включен upload_progress=On в $WEB_INI (mod_php/CGI, перекрывает php.ini) -> задайте =0."
        CRIT_HITS=$((CRIT_HITS+1))
    fi
done

# Проверка индивидуальных конфигов: php-bin сайтов, пулов fpm и .user.ini в корнях сайтов
# maxdepth 5: /var/www/u(1)/data(2)/www(3)/site(4)/.user.ini(5) — иначе .user.ini теряется
FP_INIS=$(find /var/www /etc/php /opt/php* /opt/fphp -maxdepth 5 -type f \( -name "php.ini" -o -name "*.conf" -o -name ".user.ini" \) 2>/dev/null | grep -E "php-bin|pool\.d|php-fpm\.d|\.user\.ini" | sort -u)

if [ -n "$FP_INIS" ]; then
    echo -e "\n  Аудит индивидуальных конфигов сайтов и пулов FASTPANEL:"
    FP_ISSUES=0
    for INI_PATH in $FP_INIS; do
        FP_UP=$(grep -E "^[[:space:]]*(session\.upload_progress\.enabled|php_admin_flag\[session\.upload_progress\.enabled\])[[:space:]]*=" "$INI_PATH" | tail -n 1 | cut -d'=' -f2- | cut -d';' -f1 | tr -d ' "')
        FP_SAVE=$(grep -E "^[[:space:]]*(session\.save_handler|php_admin_value\[session\.save_handler\])[[:space:]]*=" "$INI_PATH" | tail -n 1 | cut -d'=' -f2- | cut -d';' -f1 | tr -d ' "')
        FP_SER=$(grep -E "^[[:space:]]*(session\.serialize_handler|php_admin_value\[session\.serialize_handler\])[[:space:]]*=" "$INI_PATH" | tail -n 1 | cut -d'=' -f2- | cut -d';' -f1 | tr -d ' "')

        if [ "$FP_UP" = "1" ] || [ "${FP_UP,,}" = "on" ]; then
            echo "     [САЙТ/ПУЛ CVE-2026-115560/126714] Включен upload_progress=On в $INI_PATH"
            CRIT_HITS=$((CRIT_HITS+1))
            FP_ISSUES=1
        fi
        if [ "$FP_SAVE" = "files" ]; then
            echo "     [ИНФО САЙТ/ПУЛ PHPAfterShell] Задан save_handler=files в $INI_PATH (дефолт; смотри условие 1)"
        fi
        if [ -n "$FP_SER" ] && [ "$FP_SER" != "php" ]; then
            echo "     [САЙТ/ПУЛ CVE-2026-115560] Нестандартный serialize_handler='$FP_SER' в $INI_PATH"
            CRIT_HITS=$((CRIT_HITS+1))
            FP_ISSUES=1
        fi
    done

    if [ "$FP_ISSUES" -eq 0 ]; then
        echo "     - Критичных переопределений уязвимых параметров в конфигах сайтов/пулов не найдено."
    fi
fi

# Проверка веб-серверов на удержание соединений с PHP-FPM (вектор CVE-2026-129289 Request Smuggling)
if [ -d /etc/nginx ]; then
    # Отсекаем закомментированные строки (примеры в дефолтных конфигах)
    KEEP_CONN=$(grep -rn "fastcgi_keep_conn[[:space:]]\+on" /etc/nginx/ 2>/dev/null | grep -vE "^[^:]+:[0-9]+:[[:space:]]*#")
    if [ -n "$KEEP_CONN" ]; then
        echo -e "\n  [УСЛОВИЕ CVE-2026-129289] В Nginx найдено 'fastcgi_keep_conn on':"
        echo "$KEEP_CONN" | sed 's/^/     /'
        echo "     -> Отключите fastcgi_keep_conn (задайте off), если патч от 19.11.2026 ещё не установлен."
        CRIT_HITS=$((CRIT_HITS+1))
    fi
fi

for APACHE_DIR in /etc/apache2 /etc/httpd; do
    if [ -d "$APACHE_DIR" ]; then
        APACHE_REUSE=$(grep -rni "enablereuse=on" "$APACHE_DIR" 2>/dev/null | grep -vE "^[^:]+:[0-9]+:[[:space:]]*#")
        if [ -n "$APACHE_REUSE" ]; then
            echo -e "\n  [УСЛОВИЕ CVE-2026-129289] В Apache найдено 'enablereuse=on':"
            echo "$APACHE_REUSE" | sed 's/^/     /'
            echo "     -> Отключите enablereuse (задайте enablereuse=off) для защиты от FastCGI Request Smuggling."
            CRIT_HITS=$((CRIT_HITS+1))
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
        WARN_HITS=$((WARN_HITS+1))
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
        CRIT_HITS=$((CRIT_HITS+1))
    fi
done < <(ps aux --no-headers)

if [ "$FOUND_SUSP" -eq 0 ]; then
    echo "  - Подозрительных процессов на хосте не найдено (контейнеры отфильтрованы)."
fi

# 6. Проверка подозрительных задач в cron у веб-пользователей
#    Внимание: не покрывает /etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly}, systemd timers и crontabs других пользователей.
echo -e "\n Проверка задач cron у веб-пользователей:"
CRON_FOUND=0
for WEB_USER in www-data apache nginx; do
    if id "$WEB_USER" &>/dev/null; then
        CRON_OUT=$(crontab -u "$WEB_USER" -l 2>/dev/null | grep -v "^#" | grep -v "^[[:space:]]*$")
        if [ -n "$CRON_OUT" ]; then
            echo "  [ТРЕВОГА] Найдены задачи cron для $WEB_USER:"
            echo "$CRON_OUT" | sed 's/^/    /'
            CRON_FOUND=1
            CRIT_HITS=$((CRIT_HITS+1))
        fi
    fi
done
if [ "$CRON_FOUND" -eq 0 ]; then
    echo "  - Подозрительных задач cron у веб-пользователей не обнаружено."
fi

# Итог и код выхода для автоматизации
echo -e "\n=================================================================="
if [ "$CRIT_HITS" -gt 0 ]; then
    echo "   ИТОГ: критичных находок: $CRIT_HITS, предупреждений: $WARN_HITS. Код выхода: 2"
    exit 2
elif [ "$WARN_HITS" -gt 0 ]; then
    echo "   ИТОГ: критичных находок нет, предупреждений: $WARN_HITS. Код выхода: 1"
    exit 1
else
    echo "   ИТОГ: находок нет. Код выхода: 0"
    exit 0
fi
