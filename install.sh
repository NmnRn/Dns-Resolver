#!/usr/bin/env bash
#
# DNS Resolver kurulum betiği (Debian/Ubuntu; Arch tabanlılar da desteklenir)
#
# Kullanım (root olarak):
#   curl -fsSL https://raw.githubusercontent.com/NmnRn/Dns-Resolver/main/install.sh | sudo bash
#
# MariaDB'yi betik yönetmesin, kendim yapılandıracağım dersen:
#   curl -fsSL .../install.sh | sudo SKIP_MARIADB=1 bash
#
# Yaptıkları:
#   1. Gerekli paketleri kurar (git — eksikse)
#   2. Depoyu /opt/DNS_RESOLVER altına klonlar (zaten varsa günceller)
#   3. Docker "dns-net" ağını (172.27.17.0/24) oluşturur
#   4. MariaDB kurulu değilse host'a kurar, konteynerlerden erişilebilir yapar
#      (bind-address + dns_user@172.27.17.% izni)
#   5. .env dosyasına DB ayarlarını yazar ve bağlantıyı test eder
#
# Not: Uygulama Docker içinde çalıştığı için host'a Python/venv kurulmaz;
# bağımlılıklar imaj build'inde (Dockerfile) kurulur.

set -euo pipefail

REPO_URL="https://github.com/NmnRn/Dns-Resolver.git"
INSTALL_DIR="/opt/DNS_RESOLVER"
DNS_NET_NAME="dns-net"
DNS_NET_SUBNET="172.27.17.0/24"
DB_HOST_IP="172.27.17.1"        # dns-net gateway'i = host'un bu ağdaki IP'si
DB_ALLOWED_FROM="172.27.17.%"   # konteynerler (.2, .3, ...) bu bloktan bağlanır
DB_NAME="dns_db"
DB_USER="dns_user"
DB_PORT="3306"

info() { echo -e "\e[1;34m[BILGI]\e[0m $*"; }
hata() { echo -e "\e[1;31m[HATA]\e[0m $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || hata "Bu betik root gerektirir: sudo ile çalıştırın."

# --- 1) Paket yöneticisi ve temel paketler -----------------------------------
if command -v apt-get >/dev/null; then
    PKG=apt
elif command -v pacman >/dev/null; then
    PKG=pacman
else
    hata "Desteklenmeyen dağıtım (apt veya pacman bulunamadı)."
fi

kur() { # kur <komut> <apt-paketi> <pacman-paketi>
    command -v "$1" >/dev/null && return 0
    info "$1 kuruluyor..."
    if [ "$PKG" = apt ]; then
        apt-get update -qq && apt-get install -y -qq "$2"
    else
        pacman -Sy --noconfirm "$3"
    fi
}

kur git git git
command -v docker >/dev/null || \
    hata "Docker kurulu değil. Önce Docker'ı kurun: https://docs.docker.com/engine/install/"

# --- 2) Depo: klonla veya güncelle --------------------------------------------
if [ -d "$INSTALL_DIR/.git" ]; then
    info "Depo zaten mevcut, güncelleniyor..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    info "Depo klonlanıyor: $INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

# --- 3) Docker ağı -------------------------------------------------------------
if docker network inspect "$DNS_NET_NAME" >/dev/null 2>&1; then
    info "Docker ağı '$DNS_NET_NAME' zaten var."
else
    info "Docker ağı '$DNS_NET_NAME' oluşturuluyor ($DNS_NET_SUBNET)..."
    docker network create --subnet="$DNS_NET_SUBNET" "$DNS_NET_NAME"
fi

# --- 4) MariaDB: kur + konteyner erişimine aç ---------------------------------
# SKIP_MARIADB=1 verilirse bu bölümün tamamı atlanır (harici/mevcut MariaDB'yi
# kendin yönetmek için). Aşağıdaki gövde girintisiz bırakıldı, blok sonu: "fi".
if [ "${SKIP_MARIADB:-0}" = "1" ]; then
info "SKIP_MARIADB=1: MariaDB adımları atlandı. Elle yapman gerekenler:"
echo "    1) MariaDB'nin $DB_HOST_IP adresini dinlemesi (bind-address = 127.0.0.1,$DB_HOST_IP)"
echo "    2) '$DB_NAME' veritabanı + '$DB_USER'@'$DB_ALLOWED_FROM' kullanıcısı ve GRANT"
echo "    3) $INSTALL_DIR/.env içine DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME değerleri"
else

if ! command -v mariadb >/dev/null && ! command -v mysql >/dev/null; then
    info "MariaDB host'a kuruluyor..."
    if [ "$PKG" = apt ]; then
        apt-get install -y -qq mariadb-server
    else
        pacman -Sy --noconfirm mariadb
        mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
    fi
fi
systemctl enable --now mariadb

MARIADB_CLI=$(command -v mariadb || command -v mysql)

# MariaDB varsayılan olarak yalnızca 127.0.0.1 dinler; konteynerler host'a
# 172.27.17.1 üzerinden geldiği için o adresi de dinlemesi gerekir.
# 10.11+ sürümler virgülle birden fazla adres destekler; public arayüz
# dinlenmez. Daha eski sürümlerde tek seçenek 0.0.0.0'dır (erişim yine de
# kullanıcı bazında yalnızca $DB_ALLOWED_FROM bloğuna açık).
if [ -d /etc/mysql/mariadb.conf.d ]; then
    CNF_DIR=/etc/mysql/mariadb.conf.d      # Debian/Ubuntu
elif [ -d /etc/my.cnf.d ]; then
    CNF_DIR=/etc/my.cnf.d                  # Arch/RHEL türevleri
else
    hata "MariaDB yapılandırma dizini bulunamadı."
fi

MARIADB_VER=$("$MARIADB_CLI" --version | grep -oP '[0-9]+\.[0-9]+' | head -1)
if [ "$(printf '%s\n10.11\n' "$MARIADB_VER" | sort -V | head -1)" = "10.11" ]; then
    BIND_VALUE="127.0.0.1,$DB_HOST_IP"
else
    BIND_VALUE="0.0.0.0"
    info "MariaDB $MARIADB_VER çoklu bind-address desteklemiyor; 0.0.0.0 kullanılıyor."
fi

# Dosya adı bilerek "zz-": config dosyaları alfabetik okunur ve aynı
# seçeneğin SON değeri kazanır. "99-" rakamla başladığı için Arch'ın
# harfle başlayan server.cnf'inden ÖNCE okunur ve ezilirdi; "zz-" hem
# Arch'ta (server.cnf'ten sonra) hem Debian'da (NN- dosyalarından sonra)
# en son okunur.
CNF_FILE="$CNF_DIR/zz-dns-resolver.cnf"
rm -f "$CNF_DIR/99-dns-resolver.cnf"   # eski script sürümünün dosyası kalmasın
if [ ! -f "$CNF_FILE" ] || ! grep -q "^bind-address = $BIND_VALUE\$" "$CNF_FILE" \
        || ! grep -q "^skip-name-resolve\$" "$CNF_FILE"; then
    info "MariaDB bind-address ayarlanıyor ($CNF_FILE -> $BIND_VALUE)..."
    cat > "$CNF_FILE" <<CNF
# DNS Resolver: dns-net konteynerlerinin host'taki MariaDB'ye erişimi için.
# Erişim izni install.sh tarafından yalnızca $DB_USER@$DB_ALLOWED_FROM kullanıcısına verilir.
# skip-name-resolve: istemciler rDNS ile değil IP ile eşleştirilir — izinlerimiz
# IP bazlı olduğundan hostname çözümlemesi yalnızca sürpriz üretir.
[mysqld]
bind-address = $BIND_VALUE
skip-name-resolve
CNF
    systemctl restart mariadb
fi

# 172.27.17.1 (dns-net köprüsü) ancak Docker başladıktan sonra var olur.
# MariaDB reboot'ta o adrese bağlanacağı için Docker'dan sonra başlamalı;
# yine de erken kalkarsa Restart=on-failure ile toparlar.
if [ "$BIND_VALUE" != "0.0.0.0" ]; then
    mkdir -p /etc/systemd/system/mariadb.service.d
    cat > /etc/systemd/system/mariadb.service.d/dns-resolver.conf <<UNIT
[Unit]
After=docker.service
Wants=docker.service

[Service]
Restart=on-failure
RestartSec=5s
UNIT
    systemctl daemon-reload
fi

# --- 5) Veritabanı + kullanıcı + .env ------------------------------------------
ENV_FILE="$INSTALL_DIR/.env"
touch "$ENV_FILE"

# Parola: yeniden çalıştırmada değişmesin diye .env'dekini koru, yoksa üret
DB_PASSWORD=$(grep -oP '^DB_PASSWORD=\K.*' "$ENV_FILE" || true)
if [ -z "$DB_PASSWORD" ]; then
    DB_PASSWORD=$(openssl rand -hex 16 2>/dev/null || head -c32 /dev/urandom | md5sum | cut -d' ' -f1)
fi

info "Veritabanı ve kullanıcı hazırlanıyor ($DB_NAME / $DB_USER@$DB_ALLOWED_FROM)..."
"$MARIADB_CLI" <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\`;
CREATE USER IF NOT EXISTS '$DB_USER'@'$DB_ALLOWED_FROM' IDENTIFIED BY '$DB_PASSWORD';
ALTER USER '$DB_USER'@'$DB_ALLOWED_FROM' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'$DB_ALLOWED_FROM';
-- 127.0.0.1 izni yalnızca aşağıdaki bağlantı testi için (konteynerler %'den gelir)
CREATE USER IF NOT EXISTS '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';
ALTER USER '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

env_yaz() { # env_yaz ANAHTAR DEGER — varsa günceller, yoksa ekler
    if grep -q "^$1=" "$ENV_FILE"; then
        sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
    else
        echo "$1=$2" >> "$ENV_FILE"
    fi
}
env_yaz DB_HOST "$DB_HOST_IP"
env_yaz DB_PORT "$DB_PORT"
env_yaz DB_USER "$DB_USER"
env_yaz DB_PASSWORD "$DB_PASSWORD"
env_yaz DB_NAME "$DB_NAME"
chmod 600 "$ENV_FILE"
info ".env dosyasına DB ayarları yazıldı."

# --- 6) Bağlantı testi -----------------------------------------------------------
# Not: host'tan 172.27.17.1'e bağlanmak yanıltıcıdır — Docker'ın MASQUERADE
# kuralı kaynak IP'yi (dns-net bloğunda olduğu için) dış IP'ye çevirir ve
# % izni eşleşmez. Konteynerler bu kurala takılmaz. Bu yüzden:
#   a) dinleyici kontrolü: MariaDB gerçekten 172.27.17.1:3306'da mı?
#   b) kimlik/parola/db testi: 127.0.0.1 üzerinden.
info "Veritabanı test ediliyor..."
if ! ss -ltn | grep -q "$DB_HOST_IP:$DB_PORT"; then
    hata "MariaDB $DB_HOST_IP:$DB_PORT dinlemiyor - $CNF_FILE okunuyor mu? Loglar: journalctl -u mariadb"
fi
info "Dinleyici doğrulandı: $DB_HOST_IP:$DB_PORT"

TEST_HATA=$("$MARIADB_CLI" -h 127.0.0.1 -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" \
        "$DB_NAME" -e "SELECT 1;" 2>&1 >/dev/null) || {
    hata "Veritabanı bağlantı testi başarısız: $TEST_HATA"
}
info "Veritabanı bağlantısı BAŞARILI."

fi  # SKIP_MARIADB bloğu sonu

echo
info "Kurulum tamamlandı. Sonraki adımlar:"
echo "    cd $INSTALL_DIR"
echo "    ./setup.sh                     # sunucu ayarları (.env) sihirbazı"
echo "    docker compose up -d --build   # çözümleyiciyi başlat"
