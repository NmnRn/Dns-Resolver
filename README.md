# Dns-

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

Sunucu varsayılan olarak `0.0.0.0:3654` üzerinde dinler (test amaçlı,
ayrıcalıksız bir port). Test etmek için:

```bash
python -c "
from dnslib import DNSRecord
q = DNSRecord.question('example.com', 'A')
a = q.send('127.0.0.1', 3654, timeout=5)
print(DNSRecord.parse(a))
"
```

## Not

Bu proje eğitim/öğrenme amaçlıdır, production kullanımı için sertleştirme
(rate limiting, DoS koruması, daha sağlam hata yönetimi vb.) gerekir.
