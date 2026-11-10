#!/bin/bash
echo "=== Универсальная проверка и защита сервера (Debian/Ubuntu/RHEL/Alma) ==="

# Определение ОС
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="$ID"
    OS_VER="$VERSION_ID"
else
    OS_ID="unknown"
    OS_VER="unknown"
fi

K_VER=$(uname -r)

# Корректное чтение статуса MPTCP через sysctl или файл
if sysctl net.mptcp.enabled >/dev/null 2>&1; then
    MPTCP=$(sysctl -n net.mptcp.enabled)
else
    MPTCP=$(cat /proc/sys/net/mptcp/enabled 2>/dev/null || echo 0)
fi

PATCHED=false

# 1. ТОЧНАЯ ПРОВЕРКА ПАТЧЕЙ ПО ДИСТРИБУТИВАМ
if [ "$OS_ID" = "ubuntu" ]; then
    CURRENT_PKG_VER=$(dpkg-query -W -f="\${Version}" linux-image-$K_VER 2>/dev/null || dpkg-query -W -f="\${Version}" linux-image-generic 2>/dev/null || echo "0")
    if [ "$OS_VER" = "24.04" ] && dpkg --compare-versions "$CURRENT_PKG_VER" ge "6.8.0-155"; then PATCHED=true; fi
    if [ "$OS_VER" = "22.04" ] && dpkg --compare-versions "$CURRENT_PKG_VER" ge "5.15.0-210"; then PATCHED=true; fi

elif [ "$OS_ID" = "debian" ]; then
    CURRENT_PKG_VER=$(dpkg-query -W -f="\${Version}" linux-image-amd64 2>/dev/null || echo "0")
    if [ "$OS_VER" = "12" ] && dpkg --compare-versions "$CURRENT_PKG_VER" ge "6.1.190"; then PATCHED=true; fi
    if [ "$OS_VER" = "13" ] && dpkg --compare-versions "$CURRENT_PKG_VER" ge "7.2.12"; then PATCHED=true; fi

elif [[ "$OS_ID" =~ ^(rhel|almalinux|rocky)$ ]]; then
    if [[ "$OS_VER" =~ ^9 ]]; then
        RELEASE_NUM=$(echo "$K_VER" | grep -o -E "5\.14\.0-[0-9]+" | cut -d - -f2)
        if [ -n "$RELEASE_NUM" ] && [ "$RELEASE_NUM" -ge 503 ]; then PATCHED=true; fi
    elif [[ "$OS_VER" =~ ^10 ]]; then
        PATCHED=true
    fi
fi

# 2. ВЫВОД ВЕРДИКТА И АВТОМАТИЧЕСКАЯ ЗАЩИТА
if [ "$PATCHED" = "true" ]; then
    echo -e "\033[0;32m[БЕЗОПАСНО] Ваша система имеет актуальные патчи ядра.\033[0m"
elif [ "$MPTCP" = "0" ]; then
    echo -e "\033[0;32m[ЗАЩИЩЕНО] Патч отсутствует, но MPTCP уже отключен в sysctl.\033[0m"
else
    echo -e "\033[0;31m[УЯЗВИМО] Система уязвима! MPTCP включен, патчей нет. Применяем защиту...\033[0m"
    sysctl -w net.mptcp.enabled=0
    echo "net.mptcp.enabled = 0" >> /etc/sysctl.d/99-disable-mptcp.conf
    echo -e "\033[0;32m[ВРЕМЕННАЯ ЗАЩИТА ПРИМЕНЕНА] MPTCP отключен. Рекомендуется обновить ядро!\033[0m"
fi
