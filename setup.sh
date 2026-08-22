#!/usr/bin/env bash
#
# Dns Python kurulum sihirbazi (EN/TR).
# Sunucu topolojisini (hangi metot acik + ic/dis portlar + cert + allowed_host +
# site_port) config/servers.json'a; sir/DB/Django ayarlarini .env'e yazar.
#
#   ./setup.sh            (interaktif)
#   SETUP_LANG=en ./setup.sh   |   SETUP_LANG=tr ./setup.sh
#
# Not: DB ayarlarini install.sh yazar (setup.sh onlari KORUR). Portu host'a acmak
# ve baslatmak icin sonrasinda:  ./start.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_PATH="$SCRIPT_DIR/.env"
CONFIG_DIR="$SCRIPT_DIR/config"
CONFIG_PATH="$CONFIG_DIR/servers.json"
EXAMPLE_PATH="$CONFIG_DIR/servers.example.json"
PY="$(command -v python3 || command -v python)"

# --------------------------------------------------------------------------- #
# Dil / Language
# --------------------------------------------------------------------------- #
L="${SETUP_LANG:-}"
if [ -z "$L" ]; then
    echo "Language / Dil:  1) English   2) Turkce"
    read -r -p "Select / Sec [1]: " _l
    case "$_l" in 2|tr|TR) L=tr ;; *) L=en ;; esac
fi
[ "$L" = tr ] || L=en

t() { # t KEY -> secili dilde metin
  case "$1" in
    title)      [ "$L" = tr ] && echo "=== Dns Python kurulum sihirbazi ===" || echo "=== Dns Python setup wizard ===" ;;
    intro)      [ "$L" = tr ] && echo "Sunucu ayarlari config/servers.json'a, sirlar .env'e yazilir." || echo "Server settings go to config/servers.json, secrets to .env." ;;
    m_udp)      echo "UDP (duz DNS / Do53)" ;;
    m_doh)      echo "DoH (DNS-over-HTTPS)" ;;
    m_dot)      echo "DoT (DNS-over-TLS)" ;;
    m_doq)      echo "DoQ (DNS-over-QUIC)" ;;
    enable_q)   [ "$L" = tr ] && echo "acik olsun mu" || echo "enable" ;;
    cport_q)    [ "$L" = tr ] && echo "  container (ic dinleme) portu" || echo "  container (internal) port" ;;
    pub_q)      [ "$L" = tr ] && echo "  host'a (disariya) yayinlansin mi" || echo "  publish to host" ;;
    eport_q)    [ "$L" = tr ] && echo "  host (dis) portu" || echo "  host (external) port" ;;
    cert_needs) [ "$L" = tr ] && echo "  (DoH/DoT/DoQ icin gecerli sertifika gerekir)" || echo "  (DoH/DoT/DoQ need a valid certificate)" ;;
    tls)        [ "$L" = tr ] && echo "-- TLS / sertifika (DoH/DoT/DoQ ortak) --" || echo "-- TLS / certificate (shared by DoH/DoT/DoQ) --" ;;
    cert_q)     [ "$L" = tr ] && echo "Sertifika (fullchain) yolu" || echo "Certificate (fullchain) path" ;;
    key_q)      [ "$L" = tr ] && echo "Ozel anahtar yolu" || echo "Private key path" ;;
    ahost_q)    [ "$L" = tr ] && echo "DNS sunucusu domain'i (DoH/DoT SNI/Host)" || echo "DNS server domain (DoH/DoT SNI/Host)" ;;
    panel)      [ "$L" = tr ] && echo "-- Web panel --" || echo "-- Web panel --" ;;
    site_q)     [ "$L" = tr ] && echo "Panel portu (127.0.0.1'e yayinlanir)" || echo "Panel port (published to 127.0.0.1)" ;;
    origin_q)   [ "$L" = tr ] && echo "Panel HTTPS adres(ler)i (Cloudflare/proxy arkasi; bos gecebilirsin)" || echo "Panel HTTPS origin(s) (behind Cloudflare/proxy; may be empty)" ;;
    keys)       [ "$L" = tr ] && echo "-- Guvenlik anahtarlari --" || echo "-- Security keys --" ;;
    secret_gen) [ "$L" = tr ] && echo "  DJANGO_SECRET_KEY uretildi." || echo "  DJANGO_SECRET_KEY generated." ;;
    logenc_q)   [ "$L" = tr ] && echo "DNS gunlugunde client_ip/domain sifrelensin mi (at-rest)" || echo "Encrypt client_ip/domain in DNS log (at-rest)" ;;
    logkey_gen) [ "$L" = tr ] && echo "  DNS_LOG_KEY uretildi — GUVENLI YERDE YEDEKLE (kaybolursa eski kayit cozulemez)." || echo "  DNS_LOG_KEY generated — BACK IT UP (losing it makes old records unreadable)." ;;
    busy)       [ "$L" = tr ] && echo "  ! ZATEN DINLENIYOR" || echo "  ! ALREADY IN USE" ;;
    free)       [ "$L" = tr ] && echo "  + bos" || echo "  + free" ;;
    wrote_json) [ "$L" = tr ] && echo "config/servers.json yazildi." || echo "config/servers.json written." ;;
    wrote_env)  [ "$L" = tr ] && echo ".env yazildi (sir/DB/Django)." || echo ".env written (secrets/DB/Django)." ;;
    start_q)    [ "$L" = tr ] && echo "Simdi baslatilsin mi (./start.sh)" || echo "Start now (./start.sh)" ;;
    done_run)   [ "$L" = tr ] && echo "Bitti. Baslatmak icin: ./start.sh" || echo "Done. To start: ./start.sh" ;;
    bad_yn)     [ "$L" = tr ] && echo "  Lutfen e/h." || echo "  Please y/n." ;;
  esac
}

ask() { local p="$1" d="$2" v; read -r -p "$p [$d]: " v; echo "${v:-$d}"; }
ask_bool() {
  local p="$1" dt="$2" d yn v
  if [ "$L" = tr ]; then [ "$dt" = true ] && d=e || d=h; yn="(e/h)"; else [ "$dt" = true ] && d=y || d=n; yn="(y/n)"; fi
  while true; do
    read -r -p "$p $yn [$d]: " v; v="${v:-$d}"
    case "$v" in e|E|evet|y|Y|yes) echo true; return;; h|H|hayir|n|N|no) echo false; return;; *) t bad_yn >&2;; esac
  done
}
port_in_use() { local port="$1" proto="$2" f; command -v ss >/dev/null 2>&1 || return 1
  [ "$proto" = u ] && f="-lunH" || f="-ltnH"; [ -n "$(ss $f "sport = :$port" 2>/dev/null)" ]; }
check_port() { local port="$1" proto="$2"; if port_in_use "$port" "$proto"; then echo "$(t busy) ($port/$proto)"; else echo "$(t free) ($port/$proto)"; fi; }

# mevcut servers.json'dan deger oku (default'a duser) / read from existing json
gj() { # gj DOTTED_PATH DEFAULT
  [ -f "$CONFIG_PATH" ] || { echo "$2"; return; }
  "$PY" - "$1" "$2" <<'PY' 2>/dev/null || echo "$2"
import json, sys
p, d = sys.argv[1], sys.argv[2]
try:
    cfg = json.load(open(__import__("os").environ["CONFIG_PATH"]))
    cur = cfg
    for k in p.split("."):
        cur = cur[k]
    print(str(cur).lower() if isinstance(cur, bool) else cur)
except Exception:
    print(d)
PY
}
export CONFIG_PATH
ge() { # ge KEY DEFAULT — .env'den oku
  [ -f "$ENV_PATH" ] && { local v; v=$(grep -E "^$1=" "$ENV_PATH" | tail -1 | cut -d= -f2-); [ -n "$v" ] && { echo "$v"; return; }; }
  echo "$2"
}

echo; t title; echo; t intro; echo

# --- Metotlar --------------------------------------------------------------- #
declare -A EN CP EP PUB
DEFC_udp=5300; DEFC_doh=44300; DEFC_dot=8853; DEFC_doq=8530
DEFE_udp=53;   DEFE_doh=443;   DEFE_dot=853;  DEFE_doq=853
for m in udp doh dot doq; do
  echo; echo ">> $(t m_$m)"
  [ "$m" = doh ] || [ "$m" = dot ] || [ "$m" = doq ] && t cert_needs
  dc="DEFC_$m"; de="DEFE_$m"
  if [ "$m" = udp ]; then
    EN[$m]=true    # UDP daima acik (temel cozumleme)
  else
    EN[$m]=$(ask_bool "  $(t enable_q)" "$(gj "methods.$m.enabled" false)")
  fi
  CP[$m]=$(ask "$(t cport_q)" "$(gj "methods.$m.container_port" "${!dc}")")
  PUB[$m]=$(ask_bool "$(t pub_q)" "$(gj "methods.$m.publish" false)")
  if [ "${PUB[$m]}" = true ]; then
    EP[$m]=$(ask "$(t eport_q)" "$(gj "methods.$m.external_port" "${!de}")")
  else
    EP[$m]=$(gj "methods.$m.external_port" "${!de}")
  fi
  # bos-port kontrolu (bilgi)
  [ "$m" = udp ] && echo "  container:$(check_port "${CP[$m]}" u)" || echo "  container:$(check_port "${CP[$m]}" t)"
done

# --- TLS / domain ----------------------------------------------------------- #
echo; t tls
cert_file=$(ask "$(t cert_q)" "$(gj cert_file /app/certificates/fullchain.pem)")
key_file=$(ask "$(t key_q)"  "$(gj key_file  /app/certificates/privkey.pem)")
allowed_host=$(ask "$(t ahost_q)" "$(gj allowed_host dns.example.com)")

# --- Panel ------------------------------------------------------------------ #
echo; t panel
site_port=$(ask "$(t site_q)" "$(gj site_port 8444)")
panel_origin=$(ask "$(t origin_q)" "$(ge DJANGO_CSRF_TRUSTED_ORIGINS '')")
if [ -n "$panel_origin" ]; then
  secure_cookies=true
  allowed_hosts=$(printf '%s' "$panel_origin" | tr ',' '\n' | sed -E 's#^https?://##; s#[:/].*$##' | paste -sd, -)
  allowed_hosts="$allowed_hosts,127.0.0.1,localhost"
else
  secure_cookies=$(ge DJANGO_SECURE_COOKIES false)
  allowed_hosts=$(ge DJANGO_ALLOWED_HOSTS '*')
fi

# --- Guvenlik anahtarlari --------------------------------------------------- #
echo; t keys
django_secret=$(ge DJANGO_SECRET_KEY '')
if [ -z "$django_secret" ]; then
  django_secret=$(openssl rand -hex 64 2>/dev/null || head -c64 /dev/urandom | od -An -tx1 | tr -d ' \n'); t secret_gen
fi
dns_log_key=$(ge DNS_LOG_KEY '')
enable_logenc=$(ask_bool "$(t logenc_q)" "$([ -n "$dns_log_key" ] && echo true || echo false)")
if [ "$enable_logenc" = true ]; then
  [ -z "$dns_log_key" ] && { dns_log_key=$(openssl rand -base64 64 2>/dev/null | tr -d '\n'); t logkey_gen; }
else
  dns_log_key=""
fi

# --- config/servers.json yaz ------------------------------------------------ #
mkdir -p "$CONFIG_DIR"
BIND=0.0.0.0 SITE_PORT="$site_port" CERT="$cert_file" KEY="$key_file" AHOST="$allowed_host" \
EN_UDP="${EN[udp]}" CP_UDP="${CP[udp]}" EP_UDP="${EP[udp]}" PUB_UDP="${PUB[udp]}" \
EN_DOH="${EN[doh]}" CP_DOH="${CP[doh]}" EP_DOH="${EP[doh]}" PUB_DOH="${PUB[doh]}" \
EN_DOT="${EN[dot]}" CP_DOT="${CP[dot]}" EP_DOT="${EP[dot]}" PUB_DOT="${PUB[dot]}" \
EN_DOQ="${EN[doq]}" CP_DOQ="${CP[doq]}" EP_DOQ="${EP[doq]}" PUB_DOQ="${PUB[doq]}" \
OUT="$CONFIG_PATH" "$PY" - <<'PY'
import json, os
b = lambda s: str(s).lower() == "true"
i = lambda s: int(s)
def m(p):
    return {"enabled": b(os.environ[f"EN_{p}"]), "container_port": i(os.environ[f"CP_{p}"]),
            "external_port": i(os.environ[f"EP_{p}"]), "publish": b(os.environ[f"PUB_{p}"])}
cfg = {
    "bind": os.environ["BIND"], "site_port": i(os.environ["SITE_PORT"]),
    "cert_file": os.environ["CERT"], "key_file": os.environ["KEY"],
    "allowed_host": os.environ["AHOST"],
    "methods": {"udp": m("UDP"), "doh": m("DOH"), "dot": m("DOT"), "doq": m("DOQ")},
}
with open(os.environ["OUT"], "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
t wrote_json

# --- .env yaz (sir/DB/Django); DB_ satirlarini KORU -------------------------- #
db_lines=""; [ -f "$ENV_PATH" ] && db_lines=$(grep '^DB_' "$ENV_PATH" || true)
log_days=$(ge LOG_DAYS 90)
{
  echo "DJANGO_ALLOWED_HOSTS=$allowed_hosts"
  echo "DJANGO_CSRF_TRUSTED_ORIGINS=$panel_origin"
  echo "DJANGO_SECURE_COOKIES=$secure_cookies"
  echo "DJANGO_DEBUG=False"
  echo "DJANGO_SECRET_KEY=$django_secret"
  echo "DNS_LOG_KEY=$dns_log_key"
  echo "LOG_DAYS=$log_days"
} > "$ENV_PATH"
[ -n "$db_lines" ] && printf '%s\n' "$db_lines" >> "$ENV_PATH"
chmod 600 "$ENV_PATH"
t wrote_env

echo
if [ "$(ask_bool "$(t start_q)" true)" = true ]; then
  exec "$SCRIPT_DIR/start.sh"
else
  t done_run
fi
