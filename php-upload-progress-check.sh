#!/usr/bin/env bash
#
# Аудит php-fpm на вектор "session.upload_progress -> подмена сессии -> десериализация".
#
# Условие 1 (обязательное): session.upload_progress.enabled = On —
#   через multipart-запрос атакующий может записать в сессию произвольные ключи.
# Условие 2 (усиливающее): рассинхрон session.serialize_handler между контекстами
#   (бинарники, пулы, .user.ini, код сайтов) — открывает путь к десериализации.
#   Важно: handler "php_serialize" сам по себе НЕ уязвим; опасно именно расхождение
#   записи и чтения (например, запись php_serialize + чтение php).
#   Упоминания handler'а в тестовых директориях vendor (Tests) игнорируются,
#   а код, выставляющий тот же handler, что и глобально, шум не поднимает.
#
# Коды выхода: 0 — защищено; 1 — предупреждение; 2 — критический риск; 3 — PHP не найден.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

is_on() {
    case "${1,,}" in
        1|on|true) return 0 ;;
        *)         return 1 ;;
    esac
}

echo "=================================================="
echo "Хост: $(hostname) | IP: $(hostname -I 2>/dev/null | awk '{print $1}')"
echo "Дата проверки: $(date '+%Y-%m-%d %H:%M:%S')"
echo "=================================================="

# Бинарники php-fpm: системные и из /opt (FASTPANEL: /opt/fphp, /opt/phpNN и т.п.)
FPM_BINS=$(find /usr/sbin /usr/local/sbin /opt -maxdepth 3 -name 'php-fpm*' -type f -executable 2>/dev/null | sort -u)
CLI_PHP=$(command -v php 2>/dev/null || true)

if [ -z "$FPM_BINS" ] && [ -n "$CLI_PHP" ]; then
    echo -e "${YELLOW}[INFO] Бинарники php-fpm не найдены. Проверяю CLI php (СПРАВОЧНО: у CLI и FPM разные php.ini).${NC}"
    FPM_BINS="$CLI_PHP"
fi

if [ -z "$FPM_BINS" ]; then
    echo -e "${YELLOW}[INFO] PHP на хосте не найден — проверять нечего.${NC}"
    exit 3
fi

UPLOAD_ON=0        # Условие 1: upload_progress включён хотя бы где-то
MISMATCH=0         # Условие 2: рассинхрон serialize_handler
WARNING_UNREADABLE=0
HANDLERS_SEEN=""

for BIN in $FPM_BINS; do
    VER=$("$BIN" -v 2>/dev/null | head -n 1 | awk '{print $2}')
    INFO=$("$BIN" -i 2>/dev/null)
    UPLOAD_PROG=$(printf '%s\n' "$INFO" | grep '^session.upload_progress.enabled' | awk -F '=> ' '{print $2}' | xargs)
    SERIALIZER=$(printf '%s\n' "$INFO" | grep '^session.serialize_handler' | awk -F '=> ' '{print $2}' | xargs)

    echo -e "\nБинарник: ${YELLOW}$BIN${NC} (Версия: ${VER:-?})"

    if [ -z "$UPLOAD_PROG" ]; then
        echo -e "  ${YELLOW}[INFO] Не удалось прочитать настройки — проверьте вручную: $BIN -i | grep upload_progress${NC}"
        WARNING_UNREADABLE=1
        continue
    fi

    echo "  -> [Условие 1] session.upload_progress.enabled = $UPLOAD_PROG"
    echo "  -> [Условие 2] session.serialize_handler       = ${SERIALIZER:-<неизвестно>}"

    if [ -n "$SERIALIZER" ]; then
        case " $HANDLERS_SEEN " in
            *" $SERIALIZER "*) : ;;
            *) HANDLERS_SEEN="$HANDLERS_SEEN $SERIALIZER" ;;
        esac
    fi

    if is_on "$UPLOAD_PROG"; then
        echo -e "  ${RED}[Условие 1 ВЫПОЛНЕНО] upload_progress включён — сессию можно подменять.${NC}"
        UPLOAD_ON=1
    else
        echo -e "  ${GREEN}[OK] Условие 1 не выполнено — вектор заблокирован на этом бинарнике.${NC}"
    fi
done

echo -e "\n--- Переопределения upload_progress в пулах FPM и .user.ini ---"
# ВАЖНО: php -i НЕ видит переопределения из pool.d, поэтому их разбираем отдельно.
POOL_UP=$(grep -rnsE 'php_(admin_)?(value|flag)[[:space:]]*(\[[^]]*\])?[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=' \
    /etc/php/*/fpm/pool.d/ /opt/*/etc/php-fpm.d/ /opt/fphp/etc/ 2>/dev/null | grep -E '\.conf:')
INI_UP=$(grep -rnsE '^\s*session\.upload_progress\.enabled[[:space:]]*=' /var/www/ 2>/dev/null | grep -E '\.user\.ini:')

while IFS= read -r LINE; do
    [ -z "$LINE" ] && continue
    VAL=$(printf '%s\n' "$LINE" | sed 's/.*=//' | xargs)
    if is_on "$VAL"; then
        echo -e "${RED}[Условие 1 ВЫПОЛНЕНО] Переопределение ВКЛЮЧАЕТ upload_progress: $LINE${NC}"
        UPLOAD_ON=1
    else
        echo -e "${GREEN}[OK] Переопределение отключает upload_progress: $LINE${NC}"
    fi
done < <(printf '%s\n%s\n' "$POOL_UP" "$INI_UP")

if [ -z "$POOL_UP" ] && [ -z "$INI_UP" ]; then
    echo -e "${GREEN}[OK] Переопределений upload_progress в пулах и .user.ini не найдено.${NC}"
fi

echo -e "\n--- Смена session.serialize_handler в коде и конфигах ---"
CODE_MATCHES=$(grep -rnw '/var/www/' -e 'session.serialize_handler' --exclude-dir={Tests,tests,Test,test} 2>/dev/null | head -n 20)
POOL_SER=$(grep -rnsE 'php_(admin_)?(value|flag)[[:space:]]*(\[[^]]*\])?[[:space:]]*session\.serialize_handler[[:space:]]*=' \
    /etc/php/*/fpm/pool.d/ /opt/*/etc/php-fpm.d/ /opt/fphp/etc/ 2>/dev/null | grep -E '\.conf:')
INI_SER=$(grep -rnsE '^\s*session\.serialize_handler[[:space:]]*=' /var/www/ 2>/dev/null | grep -E '\.user\.ini:')

if [ -n "$CODE_MATCHES" ]; then
    echo -e "${YELLOW}[Условие 2] В коде найдены упоминания session.serialize_handler (ограничение вывода: 20 строк):${NC}"
    echo "$CODE_MATCHES"
else
    echo -e "${GREEN}[OK] В коде сайтов смена serialize_handler не обнаружена.${NC}"
fi

if [ -n "$POOL_SER" ]; then
    echo -e "${YELLOW}[Условие 2] serialize_handler переопределён в пулах FPM:${NC}"
    echo "$POOL_SER"
fi
if [ -n "$INI_SER" ]; then
    echo -e "${YELLOW}[Условие 2] serialize_handler переопределён в .user.ini:${NC}"
    echo "$INI_SER"
fi

# Собираем все встреченные значения handler'а (бинарники + явные переопределения)
for H in $POOL_SER; do
    V=$(printf '%s\n' "$H" | sed 's/.*=//' | xargs)
    [ -n "$V" ] && case " $HANDLERS_SEEN " in *" $V "*) : ;; *) HANDLERS_SEEN="$HANDLERS_SEEN $V" ;; esac
done
for H in $INI_SER; do
    V=$(printf '%s\n' "$H" | sed 's/.*=//' | xargs)
    [ -n "$V" ] && case " $HANDLERS_SEEN " in *" $V "*) : ;; *) HANDLERS_SEEN="$HANDLERS_SEEN $V" ;; esac
done

set -- $HANDLERS_SEEN
NUM_HANDLERS=$#

# Код трогает handler? Сравниваем выставляемые значения с глобальными:
# код, ставящий тот же handler, что и везде (например, тестовые фикстуры фреймворков), шумить не будет.
CODE_NEW_VALUE=""
if [ -n "$CODE_MATCHES" ]; then
    for V in $(printf '%s\n' "$CODE_MATCHES" | sed 's/^[^:]*:[0-9]*://' | grep -oE "\b(php|php_serialize|php_binary|wddx)\b" | sort -u); do
        case " $HANDLERS_SEEN " in
            *" $V "*) : ;;
            *) CODE_NEW_VALUE="$V" ;;
        esac
    done
fi

if [ "$NUM_HANDLERS" -gt 1 ] || [ -n "$CODE_NEW_VALUE" ]; then
    MISMATCH=1
    echo -e "\n${RED}[Условие 2 ВЫПОЛНЕНО] Найдены разные serialize_handler в разных контекстах:${NC}"
    for H in $HANDLERS_SEEN; do echo "  - $H"; done
    [ -n "$CODE_NEW_VALUE" ] && echo -e "  Код выставляет: ${RED}$CODE_NEW_VALUE${NC}"
else
    echo -e "\n${GREEN}[OK] Условие 2 не выполнено — serialize_handler един по всем контекстам.${NC}"
    if [ -n "$POOL_SER" ] || [ -n "$INI_SER" ]; then
        echo -e "${YELLOW}[INFO] Переопределения handler'а есть, но значение совпадает с глобальным.${NC}"
    fi
fi

echo -e "\n=================================================="
if [ "$UPLOAD_ON" -eq 1 ] && [ "$MISMATCH" -eq 1 ]; then
    echo -e "ИТОГ: ${RED}КРИТИЧЕСКИЙ РИСК — выполнены ОБА условия (upload_progress + рассинхрон handler'ов)${NC}"
    EXIT_CODE=2
elif [ "$UPLOAD_ON" -eq 1 ]; then
    echo -e "ИТОГ: ${YELLOW}ПРЕДУПРЕЖДЕНИЕ — upload_progress включён (подмена сессии возможна), рассинхрон handler'ов не найден${NC}"
    EXIT_CODE=1
elif [ "$WARNING_UNREADABLE" -eq 1 ]; then
    echo -e "ИТОГ: ${YELLOW}ТРЕБУЕТСЯ РУЧНАЯ ПРОВЕРКА — часть настроек прочитать не удалось${NC}"
    EXIT_CODE=1
else
    echo -e "ИТОГ: ${GREEN}СЕРВЕР ЗАЩИЩЁН ОТ ЭТОГО ВЕКТОРА АТАКИ${NC}"
    EXIT_CODE=0
fi
echo "=================================================="
exit $EXIT_CODE
