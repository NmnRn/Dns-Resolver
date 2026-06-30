# Dns-

![version](https://img.shields.io/badge/version-v1-blue)
![python](https://img.shields.io/badge/python-3.13-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Python ile yazılmış, sıfırdan recursive DNS resolver (v1).

Bir üst DNS'e (örn. 8.8.8.8) yönlendirme yapmaz; gelen sorguyu root sunuculardan
başlatıp TLD ve authoritative sunucuları sırayla takip ederek kendisi çözer.

## Özellikler

- 13 root sunucu (root hints) ile başlayan recursive çözümleme
- NS referral'larını takip etme; glue record verilmeyen NS'leri (örn. üçüncü
  parti nameserver'lar) ayrıca resolve ederek IP'lerine ulaşma
- TTL bazlı basit bellek içi cache
- `dnslib` tabanlı gerçek bir UDP DNS sunucusu (`BaseResolver` + `DNSServer`)

## Kurulum

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Çalıştırma

```bash
python app.py
```

Sunucu, proje kökündeki `.env` dosyasındaki `UDP_PORT` değerinde dinler.
İlk çalıştırmada `.env` yoksa otomatik oluşturulur (varsayılan
`UDP_PORT=53` — ayrıcalıklı bir port, root/sudo gerektirir). Test ederken
ayrıcalıksız bir port kullanmak için `.env` dosyasında `UDP_PORT`'u örn.
`3654` olarak değiştirebilirsin.

```bash
python -c "
import os
from dnslib import DNSRecord
q = DNSRecord.question('example.com', 'A')
a = q.send('127.0.0.1', int(os.getenv('UDP_PORT', 3654)), timeout=5)
print(DNSRecord.parse(a))
"
```

## Lisans

[MIT](LICENSE)

## Not

Bu proje eğitim/öğrenme amaçlıdır, production kullanımı için sertleştirme
(rate limiting, DoS koruması, daha sağlam hata yönetimi vb.) gerekir.
