# Dns-

![python](https://img.shields.io/badge/python-3.13%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Python ile sıfırdan yazılmış, gerçek bir **recursive DNS resolver**.

Bir üst DNS'e (8.8.8.8 gibi) yönlendirme yapan basit bir forwarder değil;
gelen sorguyu root sunuculardan başlatıp TLD ve authoritative sunucuları
sırayla takip ederek kendisi çözer. Hem ham UDP/TCP DNS hem de
DNS-over-HTTPS (DoH) olarak sunulabilir.

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
- **Çoklu sunucu mimarisi** — UDP/TCP ve DoH sunucuları bağımsız açılıp
  kapatılabilir (`.env`), ikisi de aynı çözümleme çekirdeğini ve cache'i
  paylaşır.
- **Güvenli varsayılanlar** — container host'a hiçbir port açmadan
  çalışır (açık resolver / amplification riskine karşı); dışa açmak
  istersen bunu bilerek, `docker-compose.yml`'de ilgili satırları
  yorumdan çıkararak yapman gerekir.
- **.env tabanlı yapılandırma** — port, bind adresi, hangi sunucuların
  aktif olduğu gibi ayarlar kod içine gömülü değil, `.env` dosyasından
  okunur; dosya yoksa otomatik oluşturulur.

## Mimari

```
app.py                  Giriş noktası: aktif sunucuları kurar, asyncio
                         event loop'unu yönetir, sinyal (SIGINT/SIGTERM)
                         ile hepsini birlikte kapatır.
servers/
  normal_udp.py          DNSCore (asıl recursive çözümleme mantığı) +
                         DNSResolver (dnslib köprüsü, UDP/TCP sunucu).
  https_server.py        DoH sunucusu (RFC 8484) - aynı DNSCore'u
                         kullanır, kendi HTTP(S) katmanını sarar.
cache_loop.py            Süresi dolmuş cache kayıtlarını periyodik
                         olarak (arka planda, async) temizler.
logs/dns_logs.py         Her sorguyu (client IP, domain, tip, sonuç)
                         stdout'a loglar - `docker logs` ile takip edilir.
db_ops/                  (Geliştirme aşamasında) MariaDB bağlantı havuzu
                         - henüz sorgu kayıtlarını tutan bir özellik
                         olarak bağlanmadı.
settings.py              .env dosyasının konumunu ve ilk oluşturmasını
                         yönetir.
```

Tüm sunucular (`servers/`) tek bir `DNSCore` instance'ını paylaşır — yani
UDP üzerinden çözülen bir domain, DoH üzerinden de cache'ten gelir (ve
tam tersi).

## Kurulum

### Yerel (venv ile)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Docker ile

```bash
docker network create dns-net   # yoksa
docker compose up -d --build
```

`docker-compose.yml`, `dns-net` adlı bir Docker network'ünün **zaten var
olduğunu** varsayar (`external: true`) — bu, container'ın Pi-hole/AdGuard
gibi başka bir DNS servisiyle aynı network üzerinden (isimle ya da sabit
IP'yle) konuşabilmesi için. Böyle bir servisin yoksa ya da farklı bir
kurulum istiyorsan `docker-compose.yml`'deki `networks:` bölümünü
ihtiyacına göre düzenle.

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
| `CERT_FILE` | `/app/certificates/fullchain.pem` | DoH için TLS sertifikası (yoksa sunucu düz HTTP'ye düşer) |
| `KEY_FILE` | `/app/certificates/privkey.pem` | DoH için TLS özel anahtarı |
| `EXTERNAL_UDP_PORT` | `53` | (Opsiyonel, sadece dışarı port açılırsa) host'un dışarıya açtığı UDP/TCP portu |
| `EXTERNAL_HTTPS_PORT` | `443` | (Opsiyonel, sadece dışarı port açılırsa) host'un dışarıya açtığı HTTPS portu |
| `LOG_DAYS` | `90` | (Şu an aktif kullanılmıyor - loglar stdout'a gidiyor, `docker logs` üzerinden takip edilir) |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | - | (Geliştirme aşamasında, henüz bağlanmadı) MariaDB bağlantı bilgileri |

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

- DoT (DNS-over-TLS, port 853) ve DoQ (DNS-over-QUIC) henüz yazılmadı.
- `db_ops/` (MariaDB) sorgu geçmişi/istatistik tutmak için hazırlanıyor,
  henüz hiçbir sunucuya bağlanmadı.
- `ttl_cache`'de proaktif eviction yok, sadece okuma sırasında ve
  periyodik temizlikte kontrol ediliyor.

## Lisans

[MIT](LICENSE)
