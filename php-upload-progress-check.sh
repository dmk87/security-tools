#!/usr/bin/env bash
#
# Аудит php-fpm на вектор "session.upload_progress -> подмена сессии -> десериализация".
# Закрытие вектора: session.upload_progress.enabled = Off и единый session.serialize_handler
# во всех версиях PHP и во всех пулах.
#
# Коды выхода: 0 — защищено; 1 — требуется внимание; 2 — php-fpm не найден.

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

# Собираем все бинарники php-fpm: системные и из /opt (FASTPANEL)
FPM_BINS=$(find /usr/sbin /usr/local/sbin /opt -maxdepth 3 -name 'php-fpm*' -type f -executable 2>/dev/null | sort -u)

CLI_PHP=$(command -v php 2>/dev/null || true)

if [ -z "$FPM_BINS" ] && [ -n "$CLI_PHP" ]; then
    echo -e "${YELLOW}[INFO] Бинарники php-fpm не найдены. Проверяю CLI php (СПРАВОЧНО: у CLI и FPM разные php.ini, вердикт для FPM недостоверен).${NC}"
    FPM_BINS="$CLI_PHP"
fi

if [ -z "$FPM_BINS" ]; then
    echo -e "${YELLOW}[INFO] PHP на хосте не найден — проверять нечего.${NC}"
    exit 2
fi

VULN_CONFIG_FOUND=0
UPLOAD_PROGRESS_ON=0
SERIALIZER_OVERRIDE=0

for BIN in $FPM_BINS; do
    VER=$("$BIN" -v 2>/dev/null | head -n 1 | awk '{print $2}')
    INFO=$("$BIN" -i 2>/dev/null)
    UPLOAD_PROG=$(printf '%s\n' "$INFO" | grep '^session.upload_progress.enabled' | awk -F '=> ' '{print $2}' | xargs)
    SERIALIZER=$(printf '%s\n' "$INFO" | grep '^session.serialize_handler' | awk -F '=> ' '{print $2}' | xargs)

    echo -e "\nБинарник: ${YELLOW}$BIN${NC} (Версия: ${VER:-?})"
    echo "  -> session.upload_progress.enabled = ${UPLOAD_PROG:-<не удалось прочитать>}"
    echo "  -> session.serialize_handler       = ${SERIALIZER:-<не удалось прочитать>}"

    if [ -z "$UPLOAD_PROG" ]; then
        echo -e "  ${YELLOW}[INFO] Не удалось получить настройки бинарника — проверьте вручную: $BIN -i | grep upload_progress${NC}"
        continue
    fi

    if is_on "$UPLOAD_PROG"; then
        echo -e "  ${RED}[ВНИМАНИЕ] upload_progress ВКЛЮЧЁН — вектор доступен.${NC}"
        VULN_CONFIG_FOUND=1
        UPLOAD_PROGRESS_ON=1
    else
        echo -e "  ${GREEN}[OK] upload_progress отключён (вектор заблокирован на этом бинарнике).${NC}"
    fi
done

echo -e "\n--- Переопределения upload_progress в пулах FPM и .user.ini ---"
POOL_HITS=$(grep -rnsE 'php_(admin_)?(value|flag)[[:space:]]*(\[[^]]*\])?[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=' \
    /etc/php/*/fpm/pool.d/ /opt/php*/etc/php-fpm.d/ 2>/dev/null | grep -E '\.conf:')
USER_INI_HITS=$(grep -rnsE '^\s*session\.upload_progress\.enabled[[:space:]]*=' /var/www/ 2>/dev/null | grep -E '\.user\.ini:')

while IFS= read -r LINE; do
    [ -z "$LINE" ] && continue
    VAL=$(printf '%s\n' "$LINE" | sed 's/.*=//' | xargs)
    if is_on "$VAL"; then
        echo -e "${RED}[ВНИМАНИЕ] Переопределение ВКЛЮЧАЕТ upload_progress: $LINE${NC}"
        VULN_CONFIG_FOUND=1
        UPLOAD_PROGRESS_ON=1
    else
        echo -e "${GREEN}[OK] Переопределение отключает upload_progress: $LINE${NC}"
    fi
done < <(printf '%s\n%s\n' "$POOL_HITS" "$USER_INI_HITS")

if [ -z "$POOL_HITS" ] && [ -z "$USER_INI_HITS" ]; then
    echo -e "${GREEN}[OK] Переопределений upload_progress в пулах и .user.ini не найдено.${NC}"
fi

echo -e "\n--- Смена session.serialize_handler в коде (/var/www) ---"
CODE_MATCHES=$(grep -rnw '/var/www/' -e 'session.serialize_handler' 2>/dev/null | head -n 20)

if [ -n "$CODE_MATCHES" ]; then
    echo -e "${YELLOW}[INFO] В коде найдено упоминание session.serialize_handler:${NC}"
    echo "$CODE_MATCHES"
    SERIALIZER_OVERRIDE=1
else
    echo -e "${GREEN}[OK] Изменений serialize_handler в коде сайтов не обнаружено.${NC}"
fi

if [ "$UPLOAD_PROGRESS_ON" -eq 1 ] && [ "$SERIALIZER_OVERRIDE" -eq 1 ]; then
    echo -e "\n${RED}[ВНИМАНИЕ] upload_progress включён И код трогает serialize_handler — возможен рассинхрон записи/чтения сессии (условие десериализации).${NC}"
    VULN_CONFIG_FOUND=1
fi

echo -e "\n=================================================="
if [ "$VULN_CONFIG_FOUND" -eq 1 ]; then
    echo -e "ИТОГ: ${RED}ТРЕБУЕТСЯ ВНИМАНИЕ — upload_progress активен хотя бы в одном контексте${NC}"
    echo "Рекомендация: session.upload_progress.enabled = Off в php.ini всех версий, во всех пулах FPM и в .user.ini;"
    echo "serialize_handler должен быть одинаков на записи и на чтении."
    exit 1
else
    echo -e "ИТОГ: ${GREEN}СЕРВЕР ЗАЩИЩЁН ОТ ЭТОГО ВЕКТОРА АТАКИ${NC}"
    exit 0
fi
