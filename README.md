# Dns Python — Kendi DNS Çözümleyicin

Sıfırdan yazılmış, **recursive** (kök → TLD → yetkili sunucuları kendisi yürüyen) bir
DNS çözümleyici + **web yönetim paneli**. AdGuard Home / Pi-hole tarzı reklam-izleyici
engelleme, ama **UDP/TCP + DoH + DoT + DoQ** dört transportu ve modern bir Django paneliyle.

> **Dal notu:** Bu dal (`dns-python-website`) **panelli TAM sürümdür**; `main` dalı panelsiz
> (yalnız çözümleyici) sürümü tutar. Kurulum/güncelleme betikleri bu dalı kullanır.

- **Çözümleme:** recursive (kendi çözer) *veya* forwarding (upstream'e iletir) — anlık seçilebilir
- **Şifreli DNS:** DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC (ortak sertifika)
- **Engelleme:** hazır blocklist katalogu + özel liste + izin listesi + DNS rewrite + koşullu
  yönlendirme + zamanlanmış engelleme + güvenli arama + kategori/servis engelleme
- **Panel:** iki temalı (açık/koyu), canlı sorgu akışı, analiz grafiği, yedekleme, kullanıcı yönetimi
- **Mahremiyet:** sorgu günlüğünde IP + domain **at-rest AES-SIV şifreleme** (opsiyonel)
- **Güvenlik:** panel **yalnız yönetici**, brute-force kilidi, güvenli çerezler, CSRF/clickjacking koruması

---

## Mimari

Tek konteyner, iki süreç (`run_all.py` yönetir):

```
┌─────────────────────────── dns-python (Docker) ───────────────────────────┐
│  1) Çözümleyici (app.py)     UDP/TCP · DoH · DoT · DoQ  →  dnslib + aioquic │
│  2) Web paneli (uvicorn)     Django ASGI                →  aiomysql (raw SQL)│
│                                                                             │
│  SQLite (/app/data, volume)  → panel auth + oturum                          │
└──────────────────────────────────┬──────────────────────────────────────┘
                                    │ dns-net (172.27.17.0/24)
                          ┌─────────┴─────────┐
                          │  MariaDB (HOST)   │  dns_db — sorgu günlüğü + ayarlar
                          │  172.27.17.1:3306 │  (konteynerler .2/.3'ten bağlanır)
                          └───────────────────┘
```

- **Resolver** şemanın sahibidir (`db_ops/db_core.py`), MariaDB'ye yazar.
- **Panel** aynı `dns_db`'yi aiomysql ile **ham SQL** ile okur/yazar (ORM değil); Django ORM
  yalnız SQLite'a (auth/oturum) dokunur. Oturum motoru: imzalı çerez.
- MariaDB **host'ta** çalışır; konteyner dns-net köprüsü (`172.27.17.1`) üzerinden erişir.

---

## Gereksinimler

- Linux (Debian/Ubuntu ya da Arch türevi) · **Docker** + compose plugin
- **MariaDB 10.11+** (çoklu bind-address için önerilir; `install.sh` kurar)
- `root`/sudo (kurulum betiği paket + servis kurar)

> Uygulama Docker içinde çalışır — host'a Python/venv kurulmaz; bağımlılıklar imaj build'inde iner.

---

## Hızlı Kurulum

```bash
# 1) Kurulum betiği: Docker + MariaDB + dns-net ağı + .env (DB) — root olarak
#    (dns-python-website = panelli tam sürüm; main = panelsiz resolver)
curl -fsSL https://raw.githubusercontent.com/NmnRn/Dns-Resolver/dns-python-website/install.sh | sudo bash

# 2) Ayar sihirbazı: sunucu topolojisi → config/servers.json, sırlar → .env
cd /opt/DNS_RESOLVER
sudo ./setup.sh

# 3) Başlat (config/servers.json'dan host port yayınını üretir + imajı derler)
sudo ./start.sh
```

> Betikleri **sudo** ile çağır: `install.sh` paket/servis kurar, `setup.sh` port-dolu
> kontrolü + `docker compose` için ayrıcalık ister. (Kullanıcın `docker` grubundaysa
> `docker compose`'u sudo'suz da çalıştırabilirsin.)

`install.sh` şunları **kontrol eder ve yapar:** Docker kurulu + daemon çalışıyor mu · MariaDB kurulu mu ·
dns-net ağı · MariaDB **bind-address'e `172.27.17.1` ekler** (mevcutları koruyarak, conf'u bozmadan;
yedekli) · `dns_user@172.27.17.%` + veritabanı + GRANT · `.env`'e DB ayarları (parola `openssl` ile) ·
**bağlantı testi** (dinleyici + kimlik).

`setup.sh` iki dosya üretir:
- **`config/servers.json`** — sunucu topolojisi: her metot (UDP/DoH/DoT/DoQ) **aç-kapa**, **iç
  (container) port**, **host'a yayın** (publish) + **dış port**, panel portu, sertifika yolları,
  DNS domain'i (`allowed_host`). Port çakışmasını `ss` ile kontrol eder.
- **`.env`** — yalnız **sır/DB/Django**: `DJANGO_SECRET_KEY` (512-bit) + `DNS_LOG_KEY` üretimi,
  CSRF/çerez ayarları. `install.sh`'in yazdığı `DB_*` satırları **korunur**.

`start.sh` `config/servers.json`'u okuyup **`docker-compose.override.yml`**'i üretir (host'a
yayınlanacak portlar + panel portu) ve `docker compose up -d --build` çalıştırır. Portu/publish'i
değiştirdiğinde yeniden `./start.sh` çalıştır.

> **TEK KAYNAK:** hangi metot açık + tüm portlar artık **`config/servers.json`** dosyasında
> (MariaDB'de/`.env`'de **değil**). Panel **Sunucular** sayfası da bu dosyaya yazar: **aç/kapa** ve
> **iç port** ~5 sn'de canlı uygulanır (resolver yeniden başlamaz); **dış port/publish** değişimi
> Docker gereği `./start.sh` ister.

---

## İlk açılış — yönetici hesabı

Paneli ilk açtığında (`http://127.0.0.1:8444`) hiç kullanıcı yoksa **Kurulum** ekranına yönlendirilir
ve **ilk hesap yönetici (superuser)** olarak oluşturulur (parola ≥ 8 karakter). Panel **tamamen
yönetici erişimlidir** — sonradan eklenen her hesap da yöneticidir.

> Panel varsayılan olarak yalnız `127.0.0.1:8444`'e publish edilir (public **değil**). Uzaktan erişim
> için SSH tüneli ya da Cloudflare Tunnel / ters proxy kullan.

> **⚠️ Domain / Cloudflare Tunnel / ters proxy arkasındaysan** (paneli `https://dns.example.com` gibi
> bir HTTPS adresten açıyorsan) — `.env`'de **`DJANGO_CSRF_TRUSTED_ORIGINS=https://dns.example.com`**
> (şema şart, sonda `/` yok; çoklu için virgülle) ve **`DJANGO_SECURE_COOKIES=True`** olmalı. Yoksa
> **ilk kurulumdaki** form gönderimi bile _"CSRF verification failed (403)"_ verir. `setup.sh` bunu sorar;
> elle eklersen ardından `./start.sh`.

---

## Yapılandırma

Sunucu topolojisi **`config/servers.json`**'da (setup.sh/start.sh/panel yazar; şablon:
`config/servers.example.json`). Sır/DB/Django ise **`.env`**'de (şablon: `.env.example`). İkisi de
git ile izlenmez.

**`config/servers.json`** — sunucu topolojisi (TEK kaynak):

| Alan | Açıklama |
|---|---|
| `methods.<m>.enabled` | Metodu aç/kapat (udp/doh/dot/doq) — **canlı** (~5 sn) |
| `methods.<m>.container_port` | Konteyner içi dinleme portu — **canlı** (~5 sn) |
| `methods.<m>.publish` + `.external_port` | Host'a yayın + dış port — **`./start.sh` ister** |
| `cert_file` / `key_file` | DoH/DoT/DoQ ortak TLS sertifikası (host'tan salt-okunur mount) |
| `allowed_host` | DoH/DoT sunucu domain'i (SNI/Host doğrulaması) |
| `site_port` | Panel portu (127.0.0.1'e publish) |

**`.env`** — sır/DB/Django:

| Değişken | Açıklama |
|---|---|
| `DB_*` | MariaDB bağlantısı (install.sh yazar) |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Domain/tünel/proxy arkasında **zorunlu** — yoksa CSRF 403 |
| `DJANGO_SECRET_KEY` | Panel gizli anahtarı (setup.sh 512-bit üretir) |
| `DNS_LOG_KEY` | Sorgu günlüğü at-rest şifreleme (boş = kapalı) |
| `DJANGO_SECURE_COOKIES` | Paneli **salt HTTPS**'te sunuyorsan `True` |

---

## Portlar

| Servis | Konteyner (vars.) | Host'a publish | Not |
|---|---|---|---|
| Panel | 8444 | **`127.0.0.1:<site_port>`** | Public değil (tünel/proxy ile eriş) |
| Do53 (UDP/TCP) | 5300 | varsayılan **kapalı** → `53` | `publish=true` ile açılır |
| DoH (**HTTP/2**) | 44300 | kapalı → `443` | Sertifika ister (yoksa düz HTTP/1.1) |
| DoT | 8853 | kapalı → `853` | Sertifika şart |
| DoQ | 8530 | kapalı → `853/udp` | Sertifika şart |

Portlar **`config/servers.json`**'da tutulur; **panel → Sunucular** sayfasından ya da `./setup.sh` ile
düzenlenir. `./start.sh` bunlardan `docker-compose.override.yml` üretir (git-izlenmez). **Varsayılan:
hiçbir DNS portu host'a açılmaz** — yalnız dns-net iç ağı (Cloudflare Tunnel bu ağdan erişir).

---

## Güvenlik notları

- **Panel yalnız yönetici** — her view `is_superuser` ister; yönetici-olmayan giriş reddedilir.
- **Açık resolver riski:** DNS portlarını public açarsan (spoofed kaynakla **DDoS amplification**
  aracı olursun) → **allow-list** (Filtreler/Ayarlar'da izinli istemci) veya **rate-limit** aç,
  ya da Cloudflare Tunnel arkasında tut.
- **Şifreli transportlar** gelen paketi TLS + protokol + `DNSRecord.parse` katmanlarından geçirir;
  geçersiz paket düşürülür. Erişim: allow/deny + rate-limit.
- **At-rest şifreleme:** `DNS_LOG_KEY` ile IP + domain diskte AES-SIV. **Anahtarı yedekle** —
  kaybolursa eski kayıtlar çözülemez.
- **Sırlar repoda yok:** `.env`, `*.pem/.key`, `secret_key.txt`, `*.sqlite3` hepsi `.gitignore`'da.
- **HTTPS'te:** `DJANGO_SECURE_COOKIES=True` yap; HSTS'i Cloudflare (SSL/TLS → Edge Certificates) ya da
  `SECURE_HSTS_SECONDS` ile aç (proxy arkasındaysan `SECURE_PROXY_SSL_HEADER` gerekir).

---

## Güncelleme

> **`git pull` TEK BAŞINA YETMEZ.** Uygulama Docker **imajından** çalışır — kod değişikliğinin
> etkin olması için imaj **yeniden derlenmeli** (`--build`). En kolayı `upgrade.sh`:

```bash
cd /opt/DNS_RESOLVER
sudo ./upgrade.sh   # git reset origin/<dal> + imajı yeniden derler; .env/override/certificates KORUNUR
```

Elle yapmak istersen:
```bash
git pull --ff-only                    # 1) kodu çek
sudo docker compose up -d --build     # 2) imajı yeniden derle + başlat  ← BU ŞART
```
`upgrade.sh` çalışan daldan (`git rev-parse HEAD`) çeker; izlenmeyen dosyalarına (`.env`,
`docker-compose.override.yml`, `certificates/`) dokunmaz.

## Geliştirme

```bash
python -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/pytest -q                       # testler
docker compose up -d --build                # CSS/şablon değişince (collectstatic)
```

- Panel CSS/JS `?v=` sürüm damgasıyla önbellek-kırma yapar; değişiklik sonrası tarayıcıda **F5**.
- Statik değişikliklerde imaj yeniden derlenmeli (collectstatic build'de çalışır).
