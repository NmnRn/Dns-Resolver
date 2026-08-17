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

# 2) Sunucu ayarları sihirbazı (.env: portlar, şifreli sunucular, güvenlik anahtarları)
cd /opt/DNS_RESOLVER
./setup.sh

# 3) Başlat
docker compose up -d --build
```

`install.sh` şunları **kontrol eder ve yapar:** Docker kurulu + daemon çalışıyor mu · MariaDB kurulu mu ·
dns-net ağı · MariaDB **bind-address'e `172.27.17.1` ekler** (mevcutları koruyarak, conf'u bozmadan;
yedekli) · `dns_user@172.27.17.%` + veritabanı + GRANT · `.env`'e DB ayarları (parola `openssl` ile) ·
**bağlantı testi** (dinleyici + kimlik).

`setup.sh` şunları sorar/yazar: dinleme portları, DoH/DoT/DoQ aç-kapa + sertifika, dışarı-port açma
(varsayılan **hayır** — açık resolver uyarısıyla), DNS log şifreleme, ve **`DJANGO_SECRET_KEY`
(512-bit) + `DNS_LOG_KEY` üretimi**.

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
> elle eklersen ardından `docker compose up -d`.

---

## Yapılandırma (`.env`)

Tüm değişkenler ve açıklamaları **`.env.example`** dosyasında. Gerçek `.env` git ile izlenmez.
Çoğu değeri `install.sh` (DB) + `setup.sh` (sunucu + anahtarlar) otomatik yazar. Öne çıkanlar:

| Değişken | Açıklama |
|---|---|
| `DB_*` | MariaDB bağlantısı (install.sh yazar) |
| `ENABLE_HTTPS/DOT/DOQ_SERVER` | Şifreli sunucuları aç (sertifika ister) |
| `CERT_FILE` / `KEY_FILE` | DoH/DoT/DoQ ortak TLS sertifikası (host'tan salt-okunur mount) |
| `EXTERNAL_*` | Host'a (dışarı) açılacak portlar — **dikkat: açık resolver riski** |
| `SITE_PORT` | Panel portu (127.0.0.1'e publish) |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Domain/tünel/proxy arkasında **zorunlu** (`https://dns.example.com`) — yoksa CSRF 403 |
| `DJANGO_SECRET_KEY` | Panel gizli anahtarı (setup.sh 512-bit üretir) |
| `DNS_LOG_KEY` | Sorgu günlüğü at-rest şifreleme (boş = kapalı) |
| `DJANGO_SECURE_COOKIES` | Paneli **salt HTTPS**'te sunuyorsan `True` |

---

## Portlar

| Servis | Konteyner | Host'a publish | Not |
|---|---|---|---|
| Panel | 8444 | **`127.0.0.1:8444`** | Public değil (tünel/proxy ile eriş) |
| Do53 (UDP/TCP) | 5300 | Varsayılan **kapalı** | `setup.sh` ile `53` açılabilir |
| DoH | 44300 | kapalı → `443` | Sertifika ister |
| DoT | 8853 | kapalı → `853` | Sertifika şart |
| DoQ | 8530 | kapalı → `853/udp` | Sertifika şart |

Dışarı portlar `docker-compose.override.yml` ile açılır (git-izlenmez; `setup.sh` üretir). **Varsayılan:
hiçbir DNS portu host'a açılmaz** — sadece dns-net iç ağı.

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
./upgrade.sh        # git reset origin/<dal> + imajı yeniden derler; .env/override/certificates KORUNUR
```

Elle yapmak istersen:
```bash
git pull --ff-only               # 1) kodu çek
docker compose up -d --build     # 2) imajı yeniden derle + başlat  ← BU ŞART
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
