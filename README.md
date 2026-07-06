# Dns-Resolver

![python](https://img.shields.io/badge/python-3.14%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Python ile sıfırdan yazılmış, gerçek bir **recursive DNS resolver**.

Bir üst DNS'e (8.8.8.8 gibi) yönlendirme yapan basit bir forwarder değil;
gelen sorguyu root sunuculardan başlatıp TLD ve authoritative sunucuları
sırayla takip ederek kendisi çözer. Ham UDP/TCP DNS'in yanında
DNS-over-HTTPS (DoH), DNS-over-TLS (DoT) ve DNS-over-QUIC (DoQ) olarak
da sunulabilir; sorgu geçmişi MariaDB'ye loglanır.

## Özellikler

- **Tam recursive çözümleme** — 13 root sunucu (root hints) ile başlar,
  NS referral'larını takip eder.
- **QNAME Minimisation** (RFC 7816 / RFC 9156) — her hop'ta tam domain
  yerine sadece gereken kadar etiket gönderilir; root/TLD gibi asıl kaydı
  bilmeyen sunucular kullanıcının tam olarak neyi sorduğunu görmez.
- **Glue olmayan NS desteği** — bir referral'da nameserver'ın IP'si
  (glue record) verilmemişse, o NS ismini ayrıca resolve ederek IP'sine
  ulaşır.
- **CNAME zinciri takibi** — CNAME ile karşılaşınca hedefi otomatik
  çözüp sonucu birleştirir.
- **Doğru RCODE ayrımı** — `NXDOMAIN` (domain yok), `NODATA` (domain var
  ama bu tipte kayıt yok) ve `SERVFAIL` (çözülemedi) durumlarını ayırt
  eder. Ara adımda gelen `NXDOMAIN` bile RFC 8020 gereği anında orijinal
  sorgu için geçerli sayılır (gereksiz ek sorgu atılmaz).
- **TCP fallback** — UDP cevabı kesilirse (`TC` bayrağı), otomatik olarak
  aynı sunucuya TCP üzerinden tekrar sorar. EDNS0 ile büyük UDP tamponu
  ilan ederek bu durumu olabildiğince önler.
- **Cache** — pozitif cevaplar RR'lerin kendi TTL'ine göre, negatif
  cevaplar (`NXDOMAIN`/`NODATA`) SOA kaydına göre belleğe alınır.
  Çok-thread'li sunucuda güvenli erişim için kilitlenir (`threading.Lock`),
  arka planda periyodik olarak süresi dolmuş kayıtlar temizlenir.
- **Üst sunucu fallback'i (DoH)** — bir hop'taki nameserver'ların tamamı
  kısa sürede timeout verirse (örn. ISP/DPI engeli ihtimaline karşı), tüm
  listeyi beklemeden DNS-over-HTTPS ile genel amaçlı üst sunuculara
  (1.1.1.1, 8.8.8.8) düşer — port 443 üzerinden gittiği için port-53
  odaklı engellemeyi atlatır.
- **DNS-over-HTTPS (DoH) sunucusu** (RFC 8484) — aynı çözümleme
  çekirdeğini HTTP(S) üzerinden de sunar, `POST /dns-query` ile ham
  wire-format DNS mesajı taşır.
- **DNS-over-TLS (DoT) sunucusu** (RFC 7858) — TLS ile sarılmış TCP
  üzerinden, 2 baytlık uzunluk önekli klasik DNS taşıması.
- **DNS-over-QUIC (DoQ) sunucusu** (RFC 9250, `aioquic` ile) — her sorgu
  kendi QUIC stream'inde, TLS 1.3 gömülü.
- **Sorgu loglama (MariaDB)** — her sorgu (domain, tip, istemci IP,
  zaman, protokol) bellekte tamponlanır ve arka planda toplu olarak
  `dns_cache` tablosuna yazılır; kapanışta tampon boşaltılır, DB
  erişilemezse olaylar sınırlı bir kuyrukta bekletilir.
- **Çoklu sunucu mimarisi** — UDP/TCP, DoH, DoT ve DoQ sunucuları
  bağımsız açılıp kapatılabilir (`.env`), hepsi aynı çözümleme
  çekirdeğini ve cache'i paylaşır.
- **Güvenli varsayılanlar** — container host'a hiçbir port açmadan
  çalışır (açık resolver / amplification riskine karşı); dışa açmak
  istersen bunu bilerek, `docker-compose.yml`'de ilgili satırları
  yorumdan çıkararak yapman gerekir.
- **.env tabanlı yapılandırma** — port, bind adresi, hangi sunucuların
  aktif olduğu gibi ayarlar kod içine gömülü değil, `.env` dosyasından
  okunur; dosya yoksa otomatik oluşturulur.

## Mimari

```
app.py                  Giriş noktası: aktif sunucuları kurar, DB havuzunu
                         açar/şemayı garanti eder, asyncio event loop'unu
                         yönetir, sinyal (SIGINT/SIGTERM) ile hepsini
                         birlikte kapatır (kapanışta son DB flush'ı dahil).
servers/
  normal_udp.py          DNSCore (asıl recursive çözümleme mantığı) +
                         DNSResolver (dnslib köprüsü, UDP/TCP sunucu).
  https_server.py        DoH sunucusu (RFC 8484) - aynı DNSCore'u
                         kullanır, kendi HTTP(S) katmanını sarar.
  dot_server.py          DoT sunucusu (RFC 7858) - TLS ile sarılmış
                         dnslib TCP sunucusu; sertifika yoksa açılmaz.
  doq_server.py          DoQ sunucusu (RFC 9250) - aioquic tabanlı;
                         sertifika yoksa açılmaz.
cache_loop.py            Süresi dolmuş cache kayıtlarını periyodik
                         olarak (arka planda, async) temizler.
logs/dns_logs.py         Her sorguyu (client IP, domain, tip, sonuç)
                         stdout'a loglar - `docker logs` ile takip edilir.
db_ops/                  MariaDB katmanı: aiomysql bağlantı havuzu
                         (DB_CON) + sorgu olaylarını tamponlayıp toplu
                         yazan DBManager. Tüm sunucular her sorguyu
                         buraya bırakır; 60 sn'de bir DB'ye flush edilir.
healthcheck.py           Docker HEALTHCHECK - aktif sunuculara gerçek
                         sorgu atarak sağlık kontrolü yapar.
settings.py              .env dosyasının konumunu ve ilk oluşturmasını
                         yönetir.
install.sh               Sunucuya tek komutla kurulum (aşağıya bak).
setup.sh                 .env ayarlarını soru-cevapla yazan sihirbaz.
upgrade.sh               Kurulu sürümü git üzerinden günceller.
```

Tüm sunucular (`servers/`) tek bir `DNSCore` instance'ını paylaşır — yani
UDP üzerinden çözülen bir domain, DoH üzerinden de cache'ten gelir (ve
tam tersi).

## Kurulum

### Sunucuya kurulum — `install.sh` (önerilen)

Debian/Ubuntu tabanlı bir sunucuda tek komut (root ister):

```bash
curl -fsSL https://raw.githubusercontent.com/NmnRn/Dns-Resolver/main/install.sh | sudo bash
```

Script sırasıyla şunları yapar ve **idempotenttir** (tekrar çalıştırmak
güvenlidir; üretilen DB parolası korunur, mevcut ayar bozulmaz):

1. Eksikse gerekli paketleri kurar (`git`; MariaDB yoksa onu da kurar).
   Docker'ın kurulu olmasını bekler, değilse anlaşılır bir hatayla durur.
2. Depoyu `/opt/DNS_RESOLVER` altına klonlar (zaten varsa `git pull`).
3. `dns-net` Docker ağını (`172.27.17.0/24`) oluşturur — container bu
   ağda sabit `172.27.17.2` IP'sini alır.
4. Host'taki MariaDB'yi container'lardan erişilebilir yapar:
   - `bind-address = 127.0.0.1,172.27.17.1` (yalnızca loopback + dns-net
     gateway'i; public arayüz **dinlenmez**. MariaDB 10.11 öncesinde
     çoklu adres desteklenmediği için 0.0.0.0'a düşer — erişim yine de
     kullanıcı bazında kısıtlıdır).
   - `dns_db` veritabanı + `dns_user@'172.27.17.%'` kullanıcısı
     (parola otomatik üretilir; yalnızca dns-net'teki container'lar
     bağlanabilir).
   - MariaDB'nin reboot'ta Docker'dan **sonra** başlaması için systemd
     drop-in'i (172.27.17.1 ancak Docker köprüyü kurunca var olur).
5. DB ayarlarını `.env` dosyasına yazar (`chmod 600`) ve `SELECT 1` ile
   bağlantıyı uçtan uca test eder.

Kurulum bittikten sonra:

```bash
cd /opt/DNS_RESOLVER
sudo ./setup.sh                     # sunucu ayarlarını (.env) soru-cevapla yaz
sudo docker compose up -d --build   # çözümleyiciyi başlat
```

`docker compose`, `.env`'deki `DB_*` değerlerini container'a kendisi
geçirir — imajın içindeki `.env` bilerek boştur.

### Elle Docker kurulumu

`install.sh` kullanmak istemiyorsan:

```bash
docker network create --subnet=172.27.17.0/24 dns-net   # yoksa
docker compose up -d --build
```

`docker-compose.yml`, `dns-net` adlı bir Docker network'ünün **zaten var
olduğunu** varsayar (`external: true`) — bu, container'ın Pi-hole/AdGuard
gibi başka bir DNS servisiyle aynı network üzerinden (isimle ya da sabit
IP'yle) konuşabilmesi için. Böyle bir servisin yoksa ya da farklı bir
kurulum istiyorsan `docker-compose.yml`'deki `networks:` bölümünü
ihtiyacına göre düzenle.

Bu yolda MariaDB'yi kendin kurup `.env`'e `DB_*` değerlerini yazman
gerekir (install.sh'ın 4-5. adımlarının elle karşılığı) — uygulama
açılışta veritabanına bağlanamazsa net bir hatayla durur.

### Yerel geliştirme (venv ile)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Sorgu loglama açılışta bir MariaDB'ye bağlanmak ister; yerelde en hızlı
yol geçici bir container'dır (kodun varsayılanlarıyla eşleşir):

```bash
docker run --rm -d --name dev-mariadb \
  -e MYSQL_ROOT_PASSWORD=password -e MYSQL_DATABASE=dns_db \
  -p 127.0.0.1:3306:3306 mariadb:11
```

Testler DB gerektirmez: `python -m pytest`.

## Yapılandırma

İlk çalıştırmada proje kökünde otomatik bir `.env` dosyası oluşturulur.
Elle de oluşturmak/düzenlemek istersen (ya da hazır bir şablon için)
`setup.sh` scriptini kullanabilirsin:

```bash
./setup.sh
```

Bu script sana ilgili ayarları soru-cevap şeklinde sorar ve `.env`
dosyasını ona göre yazar.

### Ortam değişkenleri

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `BIND_ADDRESS` | `0.0.0.0` (Docker) / `127.0.0.1` (yerel) | Sunucuların dinleyeceği IP |
| `CONTAINER_UDP_PORT` | `5300` | UDP/TCP DNS sunucusunun **container içi** portu |
| `CONTAINER_HTTPS_PORT` | `44300` | DoH sunucusunun **container içi** portu |
| `ENABLE_UDP_SERVER` | `true` | UDP/TCP DNS sunucusu açık mı |
| `ENABLE_HTTPS_SERVER` | `false` | DoH sunucusu açık mı (sertifika hazır olmadan `true` yapma) |
| `ALLOWED_HOST` | `dns.example.com` | DoH sunucusunun kabul edeceği `Host` header'ı — bu domain dışındaki isteklere `404` döner |
| `ENABLE_DOT_SERVER` | `false` | DoT sunucusu açık mı (sertifika şart; yoksa açılmaz) |
| `ENABLE_DOQ_SERVER` | `false` | DoQ sunucusu açık mı (sertifika şart; yoksa açılmaz) |
| `CONTAINER_DOT_PORT` | `8853` | DoT sunucusunun **container içi** portu |
| `CONTAINER_DOQ_PORT` | `8530` | DoQ sunucusunun **container içi** portu |
| `CERT_FILE` | `/app/certificates/fullchain.pem` | DoH/DoT/DoQ için TLS sertifikası (DoH sertifikasız düz HTTP'ye düşer, DoT/DoQ açılmaz) |
| `KEY_FILE` | `/app/certificates/privkey.pem` | TLS özel anahtarı |
| `EXTERNAL_UDP_PORT` | `53` | (Opsiyonel, sadece dışarı port açılırsa) host'un dışarıya açtığı UDP/TCP portu |
| `EXTERNAL_HTTPS_PORT` | `443` | (Opsiyonel, sadece dışarı port açılırsa) host'un dışarıya açtığı HTTPS portu |
| `EXTERNAL_DOT_PORT` / `EXTERNAL_DOQ_PORT` | `853` | (Opsiyonel, sadece dışarı port açılırsa) DoT (tcp) / DoQ (udp) dış portları |
| `LOG_DAYS` | `90` | (Şu an aktif kullanılmıyor - loglar stdout'a gidiyor, `docker logs` üzerinden takip edilir) |
| `DB_HOST` | `172.27.17.1` (compose) / `localhost` (yerel) | MariaDB adresi — install.sh `.env`'e yazar |
| `DB_PORT` | `3306` | MariaDB portu |
| `DB_USER` / `DB_PASSWORD` | `dns_user` / install.sh üretir | Sorgu loglarını yazan DB kullanıcısı |
| `DB_NAME` | `dns_db` | Sorgu loglarının tutulduğu veritabanı |

## DoH sunucusunu dış erişime (Cloudflare Tunnel vb.) açmak

1. `dns.numaneren.me` gibi bir domain'i sunucunun IP'sine yönlendir.
2. Domain için Let's Encrypt sertifikası al (DNS-01 doğrulamasıyla,
   `certbot-dns-cloudflare` gibi bir eklentiyle otomatik yenilenebilir).
3. Sertifika dosyalarını `docker-compose.yml`'de bir volume ile
   `CERT_FILE`/`KEY_FILE`'ın gösterdiği yola mount et.
4. `.env`'de `ENABLE_HTTPS_SERVER=true` ve `ALLOWED_HOST=<domain>` yap.
5. Cloudflare Tunnel'ı, public hostname'i container'ın `dns-net` üzerindeki
   sabit IP'sine (`CONTAINER_HTTPS_PORT`) yönlendirecek şekilde ayarla —
   bu, host'ta hiçbir port açmadan çalışır.

## Host'a doğrudan (Cloudflare olmadan) port açmak

Varsayılan olarak container host'a hiçbir port açmaz — sadece aynı Docker
network'ündeki diğer container'lardan erişilebilir. Doğrudan internetten
(örn. `dig @<sunucu-ip> example.com` ile) erişilebilir olmasını istersen,
`docker-compose.yml`'deki yorum satırı yapılmış `ports:` bloğunu aç:

```yaml
ports:
  - "${EXTERNAL_UDP_PORT:-53}:${CONTAINER_UDP_PORT:-5300}/udp"
  - "${EXTERNAL_UDP_PORT:-53}:${CONTAINER_UDP_PORT:-5300}/tcp"
  - "${EXTERNAL_HTTPS_PORT:-443}:${CONTAINER_HTTPS_PORT:-44300}/tcp"
```

**Dikkat:** bunu açmak, sunucunu herkesin kullanabileceği bir "açık
resolver" hâline getirir — bu, DNS amplification DDoS saldırılarında
kötüye kullanılabilecek bilinen bir risktir. Sadece ne yaptığını bilerek
ve gerekli önlemleri (rate limiting, IP kısıtlaması vb.) aldıktan sonra aç.

## Bilinen eksikler / yol haritası

- **Blocklist / whitelist filtreleme** — sorgu, çözümlemeye girmeden
  DB'den beslenen listelerle karşılaştırılacak (DNS sinkhole); planlandı.
- **Web yönetim paneli (Django)** — sorgu istatistikleri ve liste
  yönetimi için; DNS tarafı bitince başlanacak.
- Cache'te proaktif eviction yok, okuma sırasında ve periyodik
  temizlikte kontrol ediliyor.

## Lisans

[MIT](LICENSE)
