set +e

# --- Degiskenler ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

REPORT_FILE="audit_report.md"
TMP_LOOP_FILE="/tmp/auditor_loop.tmp"

# Mod Degiskeni (Fix modu kapali baslar)
FIX_MODE=0
if [ "$1" = "--fix" ]; then
    FIX_MODE=1
fi

DEFAULT_CONFIG="/etc/cloudflared/config.yml"
# Eger parametre --fix ise varsayilan config, degilse 1. parametre configdir
if [ "$1" = "--fix" ]; then
    CONFIG_FILE="${2:-$DEFAULT_CONFIG}"
else
    CONFIG_FILE="${1:-$DEFAULT_CONFIG}"
fi

# Sayaclar ve Bufferlar
CRITICAL_COUNT=0
WARN_COUNT=0
BUFFER_CRITICAL=""

# --- Yardimci Fonksiyonlar ---

log() {
    local level="$1"
    local message="$2"
    
    case "$level" in
        "CRITICAL")
            printf "${RED}[CRITICAL]${NC} %s\n" "$message"
            CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
            ;;
        "WARN")
            printf "${YELLOW}[WARN]${NC}     %s\n" "$message"
            WARN_COUNT=$((WARN_COUNT + 1))
            ;;
        "INFO")
            printf "${BLUE}[INFO]${NC}     %s\n" "$message"
            ;;
        "PASS")
            printf "${GREEN}[OK]${NC}       %s\n" "$message"
            ;;
        "FIX")
            printf "${GREEN}[FIXED]${NC}    %s\n" "$message"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

header() {
    printf "\n${BOLD}=== %s ===${NC}\n" "$1"
}

# ==============================================================================
# OTO-ONARIM FONKSIYONU (SAFE FIX)
# ==============================================================================
apply_fixes() {
    header "OTOMATIK ONARIM (--fix)"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        log "WARN" "Config dosyasi yok, onarim yapilamaz."
        return
    fi

    # 1. Yedek Al
    BACKUP_FILE="${CONFIG_FILE}.bak.$(date +%s)"
    cp "$CONFIG_FILE" "$BACKUP_FILE"
    log "INFO" "Yedek alindi: $BACKUP_FILE"

    # 2. Dosya Izinlerini Duzelt (chmod 600)
    # Sadece root veya sahibi okuyabilsin
    chmod 600 "$CONFIG_FILE"
    log "FIX" "Dosya izinleri 600 (guvenli) yapildi."

    # 3. Catch-all (404) Kurali Ekle
    if ! grep -q "http_status:404" "$CONFIG_FILE"; then
        log "INFO" "Catch-all kurali eksik, ekleniyor..."
        
        # Dosyanin sonuna yeni satir ekleyip kurali basiyoruz.
        # YAML indentation riskli oldugu icin standart 2 bosluk birakiyoruz.
        printf "\n  - service: http_status:404\n" >> "$CONFIG_FILE"
        
        log "FIX" "Catch-all (404) kurali config dosyasina eklendi."
        log "WARN" "Lutfen dosyayi kontrol edin (indentation hatasi olmamali)."
    else
        log "INFO" "Catch-all kurali zaten var, islem yapilmadi."
    fi

    printf "\n${BOLD}ONEMLI: Degisikliklerin aktif olmasi icin servisi yeniden baslatin:${NC}\n"
    printf "/etc/init.d/cloudflared restart\n"
}

# ==============================================================================
# ANA DENETIM DONGUSU
# ==============================================================================
printf "${BOLD}Cloudflared Tunnel Auditor v3.0${NC}\n"

# ... (Burasi standart denetim kodlari, onceki versiyonla ayni) ...
# Ozet tutmak icin hizlica geciyorum

# 1. Dosya Izinleri
check_perms() {
    local file="$1"
    if [ ! -f "$file" ]; then return; fi
    # Stat yoksa basit ls ile bakilabilir ama biz stat var sayalim veya es gecelim
    if command -v stat >/dev/null 2>&1; then
        perms=$(stat -c "%a" "$file" 2>/dev/null)
        if [ "$perms" -ge 644 ]; then
            log "CRITICAL" "$file herkese acik ($perms)!"
        else
            log "PASS" "$file izinleri guvenli ($perms)."
        fi
    fi
}
# Config izni kontrolu
check_perms "$CONFIG_FILE"

# 2. Yapilandirma Analizi
if [ -f "$CONFIG_FILE" ]; then
    if grep -q "http_status:404" "$CONFIG_FILE"; then
         log "PASS" "Catch-all (404) kurali mevcut."
    else
         log "CRITICAL" "Catch-all (404) kurali YOK!"
    fi
    
    # HTTP Kontrolu
    grep "service:" "$CONFIG_FILE" | grep -v "http_status:404" > "$TMP_LOOP_FILE"
    while read -r line; do
        svc=$(echo "$line" | awk '{print $2}' | tr -d '"' | tr -d "'")
        if echo "$svc" | grep -q "^http://"; then
            log "CRITICAL" "Guvensiz HTTP: $svc"
        fi
    done < "$TMP_LOOP_FILE"
    rm -f "$TMP_LOOP_FILE"
else
    log "CRITICAL" "Config dosyasi bulunamadi!"
fi

# ==============================================================================
# SONUC VE FIX KARARI
# ==============================================================================
header "SONUC"

printf "${RED}CRITICAL : %d${NC}\n" "$CRITICAL_COUNT"

if [ "$FIX_MODE" -eq 1 ]; then
    # Fix modu aktifse onarimi baslat
    apply_fixes
elif [ "$CRITICAL_COUNT" -gt 0 ]; then
    # Fix modu kapali ama hata varsa oner
    printf "\n${YELLOW}[ONERI] Hatalari otomatik duzeltmek icin su komutu calistirin:${NC}\n"
    printf "./auditor.sh --fix\n"
fi