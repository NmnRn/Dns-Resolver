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

# Evet/hayır sorusu; varsayılan HAYIR. "curl | bash" akışında stdin betiğin
# kendisi olduğundan soruyu /dev/tty'den okur; tty yoksa (ör. otomasyon)
# soru sormadan varsayılanla devam eder.
sor_eh() {
    local cevap=""
    # İstem stdout'a yazılır (read -p stderr'e yazar ve aşağıdaki 2>/dev/null
    # onu da yutup soruyu görünmez yapardı); yalnızca tty-yok hatası susturulur.
    printf '%s (e/h) [h]: ' "$1"
    if { read -r cevap < /dev/tty; } 2>/dev/null; then
        :
    else
        echo "h  (tty yok, varsayılan seçildi)"
    fi
    case "${cevap:-h}" in e|E|evet|Evet|y|Y|yes) return 0 ;; *) return 1 ;; esac
}

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
kur curl curl curl

# Docker yoksa kur: apt tarafında resmi convenience script (docker-ce +
# compose plugin), Arch tarafında pacman paketleri.
if ! command -v docker >/dev/null; then
    info "Docker kuruluyor..."
    if [ "$PKG" = apt ]; then
        curl -fsSL https://get.docker.com | sh
    else
        pacman -Sy --noconfirm docker docker-compose
    fi
fi
systemctl enable --now docker 2>/dev/null || true
command -v docker >/dev/null || \
    hata "Docker kurulamadı. Elle kurun: https://docs.docker.com/engine/install/"
# Kurulu olmak yetmez: daemon gerçekten yanıt veriyor mu?
docker info >/dev/null 2>&1 || \
    hata "Docker daemon çalışmıyor. Başlatın: sudo systemctl start docker"

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
# 172.27.17.1 üzerinden geldiği için o adresin de dinlenmesi gerekir.
if [ -d /etc/mysql/mariadb.conf.d ]; then
    CNF_DIR=/etc/mysql/mariadb.conf.d      # Debian/Ubuntu
elif [ -d /etc/my.cnf.d ]; then
    CNF_DIR=/etc/my.cnf.d                  # Arch/RHEL türevleri
else
    hata "MariaDB yapılandırma dizini bulunamadı."
fi

# Kendi eklenti dosyamız (alfabetik en son okunur, kazanır) SADECE
# skip-name-resolve içerir; bind-address'e KARIŞMAZ. Eski sürüm buraya
# bind-address de yazıp kullanıcının/paketin adreslerini eziyordu (ör.
# 172.17.0.1 kayboluyordu) — o satırı çıkarıyoruz ki alttaki mevcut bind
# ayarı yeniden etkin olsun, sonra ona 172.27.17.1'i EKLEYELİM.
CNF_FILE="$CNF_DIR/zz-dns-resolver.cnf"
rm -f "$CNF_DIR/99-dns-resolver.cnf"   # eski script sürümünün dosyası
if ! grep -qx "skip-name-resolve" "$CNF_FILE" 2>/dev/null \
        || grep -qi "bind-address" "$CNF_FILE" 2>/dev/null; then
    info "MariaDB eklenti ayarı yazılıyor ($CNF_FILE: skip-name-resolve)..."
    cat > "$CNF_FILE" <<CNF
# DNS Resolver eklemesi — bind-address'e KARIŞMAZ (o mevcut dosyada yönetilir).
# skip-name-resolve: istemciler rDNS yerine IP ile eşleştirilir (izinler IP bazlı).
[mysqld]
skip-name-resolve
CNF
    systemctl restart mariadb
fi

# --- bind-address: mevcut adresleri KORU, 172.27.17.1 EKLE -------------------
# @@bind_address MariaDB'nin şu an gerçekten dinlediği değerdir (hangi dosyadan
# geldiğinden bağımsız). Buna dokunmadan yalnızca eksikse ekleriz.
CURRENT_BIND=$("$MARIADB_CLI" -N -B -e "SELECT @@bind_address;" 2>/dev/null || true)

if [ "$CURRENT_BIND" = "0.0.0.0" ] \
        || printf '%s' "$CURRENT_BIND" | tr ',' '\n' | grep -qx "$DB_HOST_IP"; then
    info "MariaDB $DB_HOST_IP adresini zaten dinliyor (bind: ${CURRENT_BIND:-127.0.0.1}); değişiklik gerekmez."
    EFFECTIVE_BIND="${CURRENT_BIND:-127.0.0.1}"
else
    # 10.11+ virgülle çoklu adres destekler; eski sürümde tek çare 0.0.0.0
    # (erişim yine kullanıcı bazında $DB_ALLOWED_FROM ile kısıtlı).
    MARIADB_VER=$("$MARIADB_CLI" --version | grep -oP '[0-9]+\.[0-9]+' | head -1)
    if [ "$(printf '%s\n10.11\n' "$MARIADB_VER" | sort -V | head -1)" = "10.11" ]; then
        BASE_BIND="${CURRENT_BIND:-127.0.0.1}"
        NEW_BIND="$BASE_BIND,$DB_HOST_IP"
        SORU="MariaDB şu an '${CURRENT_BIND:-127.0.0.1}' dinliyor. Buna $DB_HOST_IP eklensin mi?"
    else
        NEW_BIND="0.0.0.0"
        SORU="MariaDB $MARIADB_VER çoklu bind-address desteklemiyor. Tüm arayüzler (0.0.0.0) dinlensin mi? (erişim yine kullanıcı bazında kısıtlı)"
    fi

    # bind-address'i tanımlayan mevcut dosyayı bul (birden çoksa alfabetik SON
    # olan etkin olandır — onu düzenleriz, yenisini sıfırdan yazmayız).
    BIND_CNF=$(grep -rliE '^[[:space:]]*bind[-_]address[[:space:]]*=' "$CNF_DIR"/*.cnf 2>/dev/null | sort | tail -1)

    if sor_eh "$SORU"; then
        if [ -n "$BIND_CNF" ]; then
            info "Mevcut bind-address düzenleniyor: $BIND_CNF -> $NEW_BIND (yedek: $BIND_CNF.bak)"
            sed -i.bak -E "s|^([[:space:]]*bind[-_]address[[:space:]]*=[[:space:]]*).*|\1$NEW_BIND|" "$BIND_CNF"
        else
            info "bind-address hiçbir dosyada tanımlı değil; $CNF_FILE dosyasına ekleniyor ($NEW_BIND)."
            printf 'bind-address = %s\n' "$NEW_BIND" >> "$CNF_FILE"
        fi
        systemctl restart mariadb
        info "Yeni bind-address: $("$MARIADB_CLI" -N -B -e "SELECT @@bind_address;" 2>/dev/null)"
        EFFECTIVE_BIND="$NEW_BIND"
    else
        info "bind-address değiştirilmedi. $DB_HOST_IP dinlenmezse konteyner bağlanamaz."
        [ -n "$BIND_CNF" ] && echo "    Elle eklemek için: $BIND_CNF içindeki bind-address satırına ',$DB_HOST_IP' ekle."
        EFFECTIVE_BIND="${CURRENT_BIND:-127.0.0.1}"
    fi
fi

# 172.27.17.1 (dns-net köprüsü) ancak Docker başladıktan sonra var olur.
# MariaDB reboot'ta o adrese bağlanacağı için Docker'dan sonra başlamalı;
# yine de erken kalkarsa Restart=on-failure ile toparlar.
if [ "$EFFECTIVE_BIND" != "0.0.0.0" ]; then
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

# Parola: yeniden çalıştırmada değişmesin diye .env'dekini koru
DB_PASSWORD=$(grep -oP '^DB_PASSWORD=\K.*' "$ENV_FILE" || true)

# Veritabanı zaten varsa sor: koru (varsayılan) ya da sıfırla
if [ -n "$("$MARIADB_CLI" -N -B -e "SHOW DATABASES LIKE '$DB_NAME';")" ]; then
    if sor_eh "Veritabanı '$DB_NAME' zaten var. SIFIRLANSIN mı? (içindeki TÜM kayıtlar silinir)"; then
        "$MARIADB_CLI" -e "DROP DATABASE \`$DB_NAME\`;"
        info "Veritabanı sıfırlandı, yeniden oluşturulacak."
    else
        info "Mevcut veritabanı olduğu gibi kullanılacak."
    fi
fi

# Kullanıcı zaten varsa sor: şifre korunsun mu, sıfırlansın mı
RESET_PW=true
if [ "$("$MARIADB_CLI" -N -B -e "SELECT COUNT(*) FROM mysql.user WHERE User='$DB_USER';")" -gt 0 ]; then
    if [ -n "$DB_PASSWORD" ]; then
        if sor_eh "Kullanıcı '$DB_USER' zaten var. Şifresi SIFIRLANSIN mı? (yeni şifre üretilir)"; then
            DB_PASSWORD=""   # aşağıda yeniden üretilir
        else
            RESET_PW=false
            info "Mevcut şifre korunuyor (.env'deki değer)."
        fi
    else
        info "Kullanıcı '$DB_USER' var ama .env'de şifre yok - şifre mecburen sıfırlanıyor."
    fi
fi
if [ -z "$DB_PASSWORD" ]; then
    DB_PASSWORD=$(openssl rand -hex 16 2>/dev/null || head -c32 /dev/urandom | md5sum | cut -d' ' -f1)
fi

ALTER_SQL=""
if [ "$RESET_PW" = true ]; then
    ALTER_SQL="ALTER USER '$DB_USER'@'$DB_ALLOWED_FROM' IDENTIFIED BY '$DB_PASSWORD';
ALTER USER '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';"
fi

info "Veritabanı ve kullanıcı hazırlanıyor ($DB_NAME / $DB_USER@$DB_ALLOWED_FROM)..."
"$MARIADB_CLI" <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\`;
CREATE USER IF NOT EXISTS '$DB_USER'@'$DB_ALLOWED_FROM' IDENTIFIED BY '$DB_PASSWORD';
-- 127.0.0.1 izni yalnızca aşağıdaki bağlantı testi için (konteynerler %'den gelir)
CREATE USER IF NOT EXISTS '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';
$ALTER_SQL
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'$DB_ALLOWED_FROM';
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
