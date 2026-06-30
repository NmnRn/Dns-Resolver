# Dns-

![version](https://img.shields.io/badge/version-v1-blue)
![python](https://img.shields.io/badge/python-3.13-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Python ile sıfırdan yazılmış, gerçek bir **recursive DNS resolver**.

Bir üst DNS'e (8.8.8.8 gibi) yönlendirme yapan basit bir forwarder değil;
gelen sorguyu root sunuculardan başlatıp TLD ve authoritative sunucuları
sırayla takip ederek kendisi çözer. `dnslib` üzerine kurulu, gerçek bir
UDP DNS sunucusu olarak çalışır.

## Özellikler

- **Tam recursive çözümleme** — 13 root sunucu (root hints) ile başlar,
  NS referral'larını takip eder.
- **Glue olmayan NS desteği** — bir referral'da nameserver'ın IP'si
  (glue record) verilmemişse, o NS ismini ayrıca resolve ederek IP'sine
  ulaşır.
- **CNAME zinciri takibi** — CNAME ile karşılaşınca hedefi otomatik
  çözüp sonucu birleştirir.
- **Doğru RCODE ayrımı** — `NXDOMAIN` (domain yok), `NODATA` (domain var
  ama bu tipte kayıt yok) ve `SERVFAIL` (çözülemedi) durumlarını ayırt
  eder.
- **TCP fallback** — UDP cevabı kesilirse (`TC` bayrağı), otomatik olarak
  aynı sunucuya TCP üzerinden tekrar sorar. EDNS0 ile büyük UDP tamponu
  ilan ederek bu durumu olabildiğince önler.
- **Cache** — pozitif cevaplar RR'lerin kendi TTL'ine göre, negatif
  cevaplar (`NXDOMAIN`/`NODATA`) SOA kaydına göre belleğe alınır.
  Çok-thread'li sunucuda güvenli erişim için kilitlenir (`threading.Lock`).
- **Üst sunucu fallback'i** — bir hop'taki nameserver'ların tamamı kısa
  sürede timeout verirse (örn. ISP/DPI engeli ihtimaline karşı), tüm
  listeyi beklemeden genel amaçlı üst sunuculara (9.9.9.9, 1.1.1.1,
  8.8.8.8) düşer.
- **Güvenli varsayılanlar** — sunucu varsayılan olarak sadece
  `127.0.0.1`'i dinler (açık resolver / amplification riskine karşı);
  dışa açmak istersen `.env`'den bilinçli olarak değiştirmen gerekir.
- **.env tabanlı yapılandırma** — port ve bind adresi gibi ayarlar kod
  içine gömülü değil, `.env` dosyasından okunur; dosya yoksa otomatik
  oluşturulur.

## Kurulum

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Yapılandırma

İlk çalıştırmada proje kökünde otomatik bir `.env` dosyası oluşturulur:

```env
UDP_PORT=53
HTTPS_PORT=443
QUIC_PORT=853
LOG_DAYS=90
```

`UDP_PORT` (varsayılan `53`, ayrıcalıklı port — root/sudo ister) ve
`BIND_ADDRESS` (varsayılan `127.0.0.1`) sunucunun nerede dinleyeceğini
belirler. Test ederken sudo gerektirmeyen bir port kullanmak istersen
`.env`'de `UDP_PORT`'u örn. `5053` yap.

## Çalıştırma

```bash
python app.py
```

Test etmek için:

```bash
python -c "
import os
from dnslib import DNSRecord
q = DNSRecord.question('example.com', 'A')
a = q.send('127.0.0.1', int(os.getenv('UDP_PORT', 53)), timeout=5)
print(DNSRecord.parse(a))
"
```

## Lisans

[MIT](LICENSE)

## Not

Bu proje eğitim/öğrenme amaçlıdır ve AI (Claude) ile birlikte
geliştirilmiştir. Production kullanımı için ek sertleştirme (rate
limiting, daha kapsamlı DoS koruması, izleme/loglama vb.) gerekir.
