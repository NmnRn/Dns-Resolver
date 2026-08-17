#!/usr/bin/env bash
#
# .env dosyasini soru-cevap seklinde olusturur/gunceller. (EN/TR)
# Creates/updates the .env file interactively. (EN/TR)
#
# Calistirmak icin / Run:  ./setup.sh   (veya / or:  bash setup.sh)
# Dil onceden: SETUP_LANG=en ./setup.sh   |   SETUP_LANG=tr ./setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_PATH="$SCRIPT_DIR/.env"
OVERRIDE_PATH="$SCRIPT_DIR/docker-compose.override.yml"

# --------------------------------------------------------------------------- #
# Dil secimi / Language selection
# --------------------------------------------------------------------------- #
L="${SETUP_LANG:-}"
if [ -z "$L" ]; then
    echo "Language / Dil:"
    echo "  1) English"
    echo "  2) Turkce"
    read -r -p "Select / Sec [1]: " _lang
    case "${_lang:-1}" in
        2|tr|TR|Turkce|turkce) L="tr" ;;
        *) L="en" ;;
    esac
fi
[ "$L" = "tr" ] || L="en"

# t KEY -> secili dildeki metni yazar / prints the string for KEY in $L
t() {
    case "$1" in
    title)          [ "$L" = tr ] && echo "=== Dns Python .env ayar sihirbazi ===" || echo "=== Dns Python .env setup wizard ===" ;;
    env_found)      [ "$L" = tr ] && echo "Mevcut bir .env dosyasi bulundu ($ENV_PATH)." || echo "An existing .env file was found ($ENV_PATH)." ;;
    overwrite_q)    [ "$L" = tr ] && echo "Uzerine yazilsin mi" || echo "Overwrite it" ;;
    cancelled)      [ "$L" = tr ] && echo "Iptal edildi, mevcut .env dosyasina dokunulmadi." || echo "Cancelled; the existing .env was left untouched." ;;
    basic)          [ "$L" = tr ] && echo "-- Temel ayarlar --" || echo "-- Basic settings --" ;;
    bind_q)         [ "$L" = tr ] && echo "Sunucunun dinleyecegi IP (Docker'da hep 0.0.0.0 kalmali)" || echo "IP the server listens on (keep 0.0.0.0 in Docker)" ;;
    udp_q)          [ "$L" = tr ] && echo "Duz DNS (Do53, UDP/TCP) sunucusunun container ici portu" || echo "Plain DNS (Do53, UDP/TCP) container port" ;;
    tls)            [ "$L" = tr ] && echo "-- TLS sertifikasi (DoH, DoT ve DoQ ORTAK kullanir) --" || echo "-- TLS certificate (shared by DoH, DoT and DoQ) --" ;;
    tls_l1)         [ "$L" = tr ] && echo "Sifreli protokoller sertifika ister. Hazir degilse varsayilani birak." || echo "Encrypted protocols need a certificate. Leave defaults if not ready." ;;
    tls_l2)         [ "$L" = tr ] && echo "DoT/DoQ sertifikasiz baslamaz, DoH duz HTTP'ye duser." || echo "DoT/DoQ won't start without one; DoH falls back to plain HTTP." ;;
    cert_q)         [ "$L" = tr ] && echo "TLS sertifika dosyasi yolu (container ici)" || echo "TLS certificate file path (inside container)" ;;
    key_q)          [ "$L" = tr ] && echo "TLS ozel anahtar dosyasi yolu (container ici)" || echo "TLS private key file path (inside container)" ;;
    doh)            [ "$L" = tr ] && echo "-- DoH (DNS-over-HTTPS) — DNS SUNUCUSU --" || echo "-- DoH (DNS-over-HTTPS) — DNS SERVER --" ;;
    doh_enable_q)   [ "$L" = tr ] && echo "DoH sunucusu acik olsun mu" || echo "Enable the DoH server" ;;
    doh_port_q)     [ "$L" = tr ] && echo "DoH sunucusunun container ici portu" || echo "DoH server container port" ;;
    doh_dom_l1)     [ "$L" = tr ] && echo "Asagidaki = DNS SUNUCUNUN domain'i (DoH istemcilerinin baglanacagi ad, or. dns.example.com)." || echo "Below = the DNS SERVER's domain (name DoH clients connect to, e.g. dns.example.com)." ;;
    doh_dom_l2)     [ "$L" = tr ] && echo "Bu, WEB PANELI domain'inden (asagida) FARKLI olabilir." || echo "This can be DIFFERENT from the WEB PANEL domain (below)." ;;
    allowed_host_q) [ "$L" = tr ] && echo "DoH / DNS sunucusu domain'i (Host kontrolu)" || echo "DoH / DNS server domain (Host check)" ;;
    dot)            [ "$L" = tr ] && echo "-- DoT (DNS-over-TLS) --" || echo "-- DoT (DNS-over-TLS) --" ;;
    dot_enable_q)   [ "$L" = tr ] && echo "DoT sunucusu acik olsun mu (TLS/TCP, sertifika sart)" || echo "Enable the DoT server (TLS/TCP, certificate required)" ;;
    dot_port_q)     [ "$L" = tr ] && echo "DoT sunucusunun container ici portu" || echo "DoT server container port" ;;
    doq)            [ "$L" = tr ] && echo "-- DoQ (DNS-over-QUIC) --" || echo "-- DoQ (DNS-over-QUIC) --" ;;
    doq_enable_q)   [ "$L" = tr ] && echo "DoQ sunucusu acik olsun mu (QUIC/UDP, sertifika sart)" || echo "Enable the DoQ server (QUIC/UDP, certificate required)" ;;
    doq_port_q)     [ "$L" = tr ] && echo "DoQ sunucusunun container ici portu" || echo "DoQ server container port" ;;
    ext)            [ "$L" = tr ] && echo "-- Disariya (host'a) port acma --" || echo "-- Publishing ports to the host --" ;;
    ext_l1)         [ "$L" = tr ] && echo "Not: bunu acmak sunucunu herkesin kullanabilecegi bir 'acik resolver'" || echo "Note: this can turn your server into an 'open resolver' usable by anyone" ;;
    ext_l2)         [ "$L" = tr ] && echo "haline getirir (DDoS amplification riski). Emin degilsen hayir de." || echo "(DDoS amplification risk). If unsure, say no." ;;
    ext_open_q)     [ "$L" = tr ] && echo "Host'a disariya port acilsin mi" || echo "Publish ports to the host" ;;
    ext_udp_q)      [ "$L" = tr ] && echo "Disariya acilacak Do53 (UDP/TCP) portu" || echo "Host port for Do53 (UDP/TCP)" ;;
    ext_https_q)    [ "$L" = tr ] && echo "Disariya acilacak DoH (HTTPS) portu" || echo "Host port for DoH (HTTPS)" ;;
    ext_dot_q)      [ "$L" = tr ] && echo "Disariya acilacak DoT (TLS/TCP) portu" || echo "Host port for DoT (TLS/TCP)" ;;
    ext_doq_q)      [ "$L" = tr ] && echo "Disariya acilacak DoQ (QUIC/UDP) portu" || echo "Host port for DoQ (QUIC/UDP)" ;;
    panel)          [ "$L" = tr ] && echo "-- WEB PANELI erisimi — DNS sunucusundan FARKLI domain olabilir --" || echo "-- WEB PANEL access — can be a DIFFERENT domain from the DNS server --" ;;
    panel_l1)       [ "$L" = tr ] && echo "Panelin acildigi HTTPS adres (or. https://webpanel.example.com) — yukaridaki DNS/DoH" || echo "The HTTPS address the panel opens at (e.g. https://webpanel.example.com) — SEPARATE from" ;;
    panel_l2)       [ "$L" = tr ] && echo "domain'inden AYRI. Domain/Cloudflare Tunnel/ters proxy arkasindaysan ZORUNLU: yoksa panel" || echo "the DNS/DoH domain above. REQUIRED behind a domain/Cloudflare Tunnel/reverse proxy: otherwise" ;;
    panel_l3)       [ "$L" = tr ] && echo "form gonderimi 'CSRF verification failed (403)' verir (ilk kurulumda bile)." || echo "panel form submits fail with 'CSRF verification failed (403)' (even on first setup)." ;;
    panel_l4)       [ "$L" = tr ] && echo "Yalniz 127.0.0.1 / SSH tuneli kullaniyorsan bos birak. Coklu adres icin virgulle ayir." || echo "Leave empty if you only use 127.0.0.1 / an SSH tunnel. Comma-separate multiple addresses." ;;
    panel_origin_q) [ "$L" = tr ] && echo "WEB PANELI public URL(ler)i (https://webpanel.example.com, bos = yerel)" || echo "WEB PANEL public URL(s) (https://webpanel.example.com, empty = local)" ;;
    panel_loc_l1)   [ "$L" = tr ] && echo "Panel yalniz host'un 127.0.0.1'ine yayinlanir (public DEGIL); SSH tuneli / ters" || echo "The panel is published only to the host's 127.0.0.1 (NOT public); reach it via SSH tunnel /" ;;
    panel_loc_l2)   [ "$L" = tr ] && echo "proxy / Cloudflare Tunnel ile erisilir. Asagidaki port o yerel yayin portudur." || echo "reverse proxy / Cloudflare Tunnel. The port below is that local publish port." ;;
    site_port_q)    [ "$L" = tr ] && echo "WEB PANELI host (local) portu" || echo "WEB PANEL host (local) port" ;;
    secret_gen)     [ "$L" = tr ] && echo "DJANGO_SECRET_KEY uretildi (kapsamli, kalici)." || echo "DJANGO_SECRET_KEY generated (strong, persistent)." ;;
    logenc)         [ "$L" = tr ] && echo "-- DNS log sifreleme (at-rest) --" || echo "-- DNS log encryption (at-rest) --" ;;
    logenc_l1)      [ "$L" = tr ] && echo "Acarsan sorgu gunlugundeki istemci IP + domain diskte sifreli tutulur (mahremiyet)." || echo "If enabled, client IP + domain in the query log are stored encrypted on disk (privacy)." ;;
    logenc_q)       [ "$L" = tr ] && echo "DNS log sifreleme acik olsun mu" || echo "Enable DNS log encryption" ;;
    logkey_gen)     [ "$L" = tr ] && echo "DNS_LOG_KEY uretildi (AES-SIV). UYARI: kaybolursa eski kayitlar cozulemez -> yedekle." || echo "DNS_LOG_KEY generated (AES-SIV). WARNING: if lost, old records can't be decrypted -> back it up." ;;
    env_written)    [ "$L" = tr ] && echo ".env dosyasi yazildi:" || echo ".env file written:" ;;
    db_preserved)   [ "$L" = tr ] && echo "Mevcut DB_ ayarlari korundu." || echo "Existing DB_ settings preserved." ;;
    ov_written)     [ "$L" = tr ] && echo "docker-compose.override.yml yazildi (disariya port acilacak)." || echo "docker-compose.override.yml written (ports will be published)." ;;
    ov_removed)     [ "$L" = tr ] && echo "docker-compose.override.yml kaldirildi (disariya port acilmiyor)." || echo "docker-compose.override.yml removed (no host ports published)." ;;
    portchk)        [ "$L" = tr ] && echo "-- Port kullanim kontrolu (host) --" || echo "-- Port availability check (host) --" ;;
    busy_note1)     [ "$L" = tr ] && echo "  NOT: Bu proje ZATEN calisiyorsa dolu gorunmesi normaldir. Aksi halde" || echo "  NOTE: If this project is ALREADY running, 'in use' is normal. Otherwise" ;;
    busy_note2)     [ "$L" = tr ] && echo "       cakisan servisi durdur ya da yukaridaki portlari degistir (./setup.sh)." || echo "       stop the conflicting service or change the ports above (./setup.sh)." ;;
    ss_missing)     [ "$L" = tr ] && echo "  (ss bulunamadi — port kontrolu atlandi; iproute2 kurabilirsin.)" || echo "  (ss not found — port check skipped; you can install iproute2.)" ;;
    cert_rem_l1)    [ "$L" = tr ] && echo "Sifreli bir sunucu (DoH/DoT/DoQ) actin - sertifika dosyalarinin" || echo "You enabled an encrypted server (DoH/DoT/DoQ) - make sure the certificate files" ;;
    cert_rem_l2)    [ "$L" = tr ] && echo "(CERT_FILE/KEY_FILE) container icinde gercekten var oldugundan emin ol" || echo "(CERT_FILE/KEY_FILE) actually exist inside the container" ;;
    cert_rem_l3)    [ "$L" = tr ] && echo "(docker-compose.yml'de bir volume ile mount edildiginden)." || echo "(mounted via a volume in docker-compose.yml)." ;;
    start_q)        [ "$L" = tr ] && echo "Simdi baslatilsin mi (docker compose up -d --build)" || echo "Start now (docker compose up -d --build)" ;;
    starting)       [ "$L" = tr ] && echo "Baslatiliyor (docker compose up -d --build)..." || echo "Starting (docker compose up -d --build)..." ;;
    running_at)     [ "$L" = tr ] && echo "Panel calisiyor:" || echo "Panel is running at:" ;;
    will_run)       [ "$L" = tr ] && echo "Baslatmak icin: docker compose up -d --build ; sonra panel:" || echo "To start: docker compose up -d --build ; then the panel:" ;;
    url_local)      [ "$L" = tr ] && echo "(sunucu icinden)" || echo "(from the server itself)" ;;
    url_tunnel)     [ "$L" = tr ] && echo "(tunel / ters proxy arkasindan)" || echo "(behind a tunnel / reverse proxy)" ;;
    start_failed)   [ "$L" = tr ] && echo "docker compose baslatilamadi (izin/daemon?). Elle: docker compose up -d --build" || echo "docker compose failed (permissions/daemon?). Manually: docker compose up -d --build" ;;
    bad_yn)         [ "$L" = tr ] && echo "Lutfen e/h gir." || echo "Please enter y/n." ;;
    *) echo "$1" ;;
    esac
}

# --------------------------------------------------------------------------- #
# Disariya port acmayi docker-compose.override.yml uzerinden yonet.
# Manage host port publishing via docker-compose.override.yml.
# --------------------------------------------------------------------------- #
write_external_ports() {
    local enable="$1"
    if [ "$enable" = "true" ]; then
        cat > "$OVERRIDE_PATH" <<'YAML'
# setup.sh tarafindan uretildi / generated by setup.sh — host'a port acar.
# .env'deki EXTERNAL_* / CONTAINER_* degiskenlerini okur. git ile izlenmez.
services:
  dns-python:
    ports:
      - "${EXTERNAL_UDP_PORT:-53}:${CONTAINER_UDP_PORT:-5300}/udp"
      - "${EXTERNAL_UDP_PORT:-53}:${CONTAINER_UDP_PORT:-5300}/tcp"
      - "${EXTERNAL_HTTPS_PORT:-443}:${CONTAINER_HTTPS_PORT:-44300}/tcp"
      - "${EXTERNAL_DOT_PORT:-853}:${CONTAINER_DOT_PORT:-8853}/tcp"
      - "${EXTERNAL_DOQ_PORT:-853}:${CONTAINER_DOQ_PORT:-8530}/udp"
YAML
    else
        rm -f "$OVERRIDE_PATH"
    fi
}

# mevcut .env'den bir degeri oku / read a value from existing .env (else default)
get_existing() {
    local key="$1" default="$2"
    if [ -f "$ENV_PATH" ]; then
        local value
        value=$(grep -E "^${key}=" "$ENV_PATH" | tail -1 | cut -d'=' -f2- || true)
        [ -n "$value" ] && echo "$value" && return
    fi
    echo "$default"
}

ask() {
    local prompt="$1" default="$2" value
    read -r -p "$prompt [$default]: " value
    echo "${value:-$default}"
}

# evet/hayir sorusu / yes-no question. TR: e/h, EN: y/n (ikisi de kabul edilir)
ask_bool() {
    local prompt="$1" default_true="$2" default value yn
    if [ "$L" = tr ]; then
        [ "$default_true" = "true" ] && default="e" || default="h"; yn="(e/h)"
    else
        [ "$default_true" = "true" ] && default="y" || default="n"; yn="(y/n)"
    fi
    while true; do
        read -r -p "$prompt $yn [$default]: " value
        value="${value:-$default}"
        case "$value" in
            e|E|evet|Evet|y|Y|yes|Yes) echo "true"; return ;;
            h|H|hayir|Hayir|n|N|no|No) echo "false"; return ;;
            *) t bad_yn >&2 ;;
        esac
    done
}

# Bir host portu DINLENIYOR mu? / Is a host port being listened on? (ss, offline)
#   $1=port  $2=proto (t|u).  ss yoksa 1 / returns 1 if ss missing.
port_in_use() {
    local port="$1" proto="$2" flag
    command -v ss >/dev/null 2>&1 || return 1
    [ "$proto" = "u" ] && flag="-lunH" || flag="-ltnH"
    [ -n "$(ss $flag "sport = :$port" 2>/dev/null)" ]
}

# $1=etiket/label  $2=port  $3=proto.  Doluysa / if busy -> ports_busy=1
check_port() {
    local label="$1" port="$2" proto="$3"
    if port_in_use "$port" "$proto"; then
        if [ "$L" = tr ]; then echo "  ! $label: $port/$proto ZATEN DINLENIYOR (baska servis olabilir)."
        else echo "  ! $label: $port/$proto ALREADY IN USE (another service?)."; fi
        ports_busy=1
    else
        if [ "$L" = tr ]; then echo "  + $label: $port/$proto bos."
        else echo "  + $label: $port/$proto free."; fi
    fi
}

echo
t title
echo

if [ -f "$ENV_PATH" ]; then
    t env_found
    overwrite=$(ask_bool "$(t overwrite_q)" "false")
    if [ "$overwrite" = "false" ]; then
        t cancelled
        exit 0
    fi
fi

echo
t basic
bind_address=$(ask "$(t bind_q)" "$(get_existing BIND_ADDRESS 0.0.0.0)")
container_udp_port=$(ask "$(t udp_q)" "$(get_existing CONTAINER_UDP_PORT 5300)")

echo
t tls
t tls_l1
t tls_l2
cert_file=$(ask "$(t cert_q)" "$(get_existing CERT_FILE /app/certificates/fullchain.pem)")
key_file=$(ask "$(t key_q)" "$(get_existing KEY_FILE /app/certificates/privkey.pem)")

echo
t doh
enable_https=$(ask_bool "$(t doh_enable_q)" "$(get_existing ENABLE_HTTPS_SERVER false)")
container_https_port=$(ask "$(t doh_port_q)" "$(get_existing CONTAINER_HTTPS_PORT 44300)")
t doh_dom_l1
t doh_dom_l2
allowed_host=$(ask "$(t allowed_host_q)" "$(get_existing ALLOWED_HOST dns.example.com)")

echo
t dot
enable_dot=$(ask_bool "$(t dot_enable_q)" "$(get_existing ENABLE_DOT_SERVER false)")
container_dot_port=$(ask "$(t dot_port_q)" "$(get_existing CONTAINER_DOT_PORT 8853)")

echo
t doq
enable_doq=$(ask_bool "$(t doq_enable_q)" "$(get_existing ENABLE_DOQ_SERVER false)")
container_doq_port=$(ask "$(t doq_port_q)" "$(get_existing CONTAINER_DOQ_PORT 8530)")

echo
t ext
t ext_l1
t ext_l2
open_external=$(ask_bool "$(t ext_open_q)" "false")
external_udp_port="$(get_existing EXTERNAL_UDP_PORT 53)"
external_https_port="$(get_existing EXTERNAL_HTTPS_PORT 443)"
external_dot_port="$(get_existing EXTERNAL_DOT_PORT 853)"
external_doq_port="$(get_existing EXTERNAL_DOQ_PORT 853)"
if [ "$open_external" = "true" ]; then
    external_udp_port=$(ask "$(t ext_udp_q)" "$external_udp_port")
    external_https_port=$(ask "$(t ext_https_q)" "$external_https_port")
    external_dot_port=$(ask "$(t ext_dot_q)" "$external_dot_port")
    external_doq_port=$(ask "$(t ext_doq_q)" "$external_doq_port")
fi

echo
t panel
t panel_l1
t panel_l2
t panel_l3
t panel_l4
panel_origin=$(ask "$(t panel_origin_q)" "$(get_existing DJANGO_CSRF_TRUSTED_ORIGINS '')")
if [ -n "$panel_origin" ]; then
    secure_cookies=true    # HTTPS domain -> panel cerezleri Secure / Secure cookies
    allowed_hosts=$(printf '%s' "$panel_origin" | tr ',' '\n' | sed -E 's#^https?://##; s#[:/].*$##' | paste -sd, -)
    allowed_hosts="$allowed_hosts,127.0.0.1,localhost"
    echo "DJANGO_ALLOWED_HOSTS = $allowed_hosts"
else
    secure_cookies="$(get_existing DJANGO_SECURE_COOKIES false)"
    allowed_hosts="$(get_existing DJANGO_ALLOWED_HOSTS '*')"
fi
t panel_loc_l1
t panel_loc_l2
site_port=$(ask "$(t site_port_q)" "$(get_existing SITE_PORT 8444)")

log_days="$(get_existing LOG_DAYS 90)"

# install.sh'in yazdigi DB_ ayarlarini koru / preserve DB_ lines written by install.sh
db_lines=""
if [ -f "$ENV_PATH" ]; then
    db_lines=$(grep '^DB_' "$ENV_PATH" || true)
fi

# --- Guvenlik anahtarlari: VARSA KORU / keep if present, else generate ---
django_secret=$(get_existing DJANGO_SECRET_KEY "")
if [ -z "$django_secret" ]; then
    django_secret=$(openssl rand -hex 64 2>/dev/null || head -c64 /dev/urandom | od -An -tx1 | tr -d ' \n')
    t secret_gen
fi
dns_log_key=$(get_existing DNS_LOG_KEY "")
echo
t logenc
t logenc_l1
enable_logenc=$(ask_bool "$(t logenc_q)" "$([ -n "$dns_log_key" ] && echo true || echo false)")
if [ "$enable_logenc" = "true" ]; then
    if [ -z "$dns_log_key" ]; then
        dns_log_key=$(openssl rand -base64 64 2>/dev/null | tr -d '\n')
        t logkey_gen
    fi
else
    dns_log_key=""
fi

cat > "$ENV_PATH" <<EOF
BIND_ADDRESS=$bind_address
CONTAINER_UDP_PORT=$container_udp_port
CONTAINER_HTTPS_PORT=$container_https_port
CONTAINER_DOT_PORT=$container_dot_port
CONTAINER_DOQ_PORT=$container_doq_port
ENABLE_UDP_SERVER=true
ENABLE_HTTPS_SERVER=$enable_https
ENABLE_DOT_SERVER=$enable_dot
ENABLE_DOQ_SERVER=$enable_doq
ALLOWED_HOST=$allowed_host
CERT_FILE=$cert_file
KEY_FILE=$key_file
EXTERNAL_UDP_PORT=$external_udp_port
EXTERNAL_HTTPS_PORT=$external_https_port
EXTERNAL_DOT_PORT=$external_dot_port
EXTERNAL_DOQ_PORT=$external_doq_port
SITE_PORT=$site_port
LOG_DAYS=$log_days
DJANGO_ALLOWED_HOSTS=$allowed_hosts
DJANGO_CSRF_TRUSTED_ORIGINS=$panel_origin
DJANGO_SECURE_COOKIES=$secure_cookies
DJANGO_SECRET_KEY=$django_secret
DNS_LOG_KEY=$dns_log_key
EOF

if [ -n "$db_lines" ]; then
    printf '%s\n' "$db_lines" >> "$ENV_PATH"
    t db_preserved
fi
chmod 600 "$ENV_PATH"   # .env SECRET_KEY + DNS_LOG_KEY iceriyor -> yalniz sahibi / owner-only

echo
echo "$(t env_written) $ENV_PATH"

write_external_ports "$open_external"
if [ "$open_external" = "true" ]; then t ov_written; else t ov_removed; fi

# --- Ayarlanan host portlari bosta mi? / Are the chosen host ports free? ---
echo
t portchk
ports_busy=0
if [ "$L" = tr ]; then _panel_lbl="Web panel"; else _panel_lbl="Web panel"; fi
check_port "$_panel_lbl" "$site_port" t
if [ "$open_external" = "true" ]; then
    check_port "Do53 (UDP)" "$external_udp_port" u
    check_port "Do53 (TCP)" "$external_udp_port" t
    [ "$enable_https" = "true" ] && check_port "DoH" "$external_https_port" t
    [ "$enable_dot" = "true" ] && check_port "DoT" "$external_dot_port" t
    [ "$enable_doq" = "true" ] && check_port "DoQ" "$external_doq_port" u
fi
if [ "$ports_busy" = "1" ]; then
    t busy_note1
    t busy_note2
elif ! command -v ss >/dev/null 2>&1; then
    t ss_missing
fi

if [ "$enable_https" = "true" ] || [ "$enable_dot" = "true" ] || [ "$enable_doq" = "true" ]; then
    echo
    t cert_rem_l1
    t cert_rem_l2
    t cert_rem_l3
fi

# --------------------------------------------------------------------------- #
# Baslat + eristigi URL'i yazdir / Start + print the access URL
# --------------------------------------------------------------------------- #
server_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$server_ip" ] || server_ip="127.0.0.1"

print_urls() {   # $1 = calisiyor mu / running?
    echo
    if [ "$1" = "running" ]; then echo "==> $(t running_at)"; else echo "==> $(t will_run)"; fi
    echo "    http://127.0.0.1:${site_port}/        $(t url_local)"
    echo "    http://${server_ip}:${site_port}/     $(t url_tunnel)"
}

echo
start_now=$(ask_bool "$(t start_q)" "false")
if [ "$start_now" = "true" ]; then
    echo; t starting
    if (cd "$SCRIPT_DIR" && docker compose up -d --build); then
        print_urls running
    else
        echo; t start_failed
        print_urls notyet
    fi
else
    print_urls notyet
fi
