# DNS Şifreleme Protokolleri: Do53, DoH, DoT, DoQ

Bu resolver, **aynı DNS çözümleme motorunu** dört farklı "kapıdan" sunar:
düz DNS (Do53), DNS-over-HTTPS (DoH), DNS-over-TLS (DoT) ve
DNS-over-QUIC (DoQ). Bu belge her birinin **ne olduğunu, nasıl çalıştığını**
ve **farklarını** anlatır.

---

## Neden şifreli DNS?

Düz DNS (port 53) **açık metindir**. Sorgun — yani "hangi sitenin IP'sini
istiyorsun" — yol boyunca herkes tarafından **okunabilir ve değiştirilebilir**:
internet sağlayıcın, kafedeki ortak Wi-Fi, aradaki router'lar... Hangi siteleri
ziyaret ettiğin baştan sona görünür, ve kötü niyetli biri araya girip seni
yanlış IP'ye yönlendirebilir.

Şifreli DNS iki şey sağlar:

- **Gizlilik:** sorgun bir TLS tüneli içinde gider; yoldaki kimse içeriğini
  göremez.
- **Bütünlük / kimlik:** sertifika sayesinde gerçekten doğru sunucuyla
  konuştuğundan emin olursun; araya girip cevabı değiştiremezler.

---

## Ortak fikir: aynı DNS, farklı boru

En önemli kavrayış şu: dört yöntem de **birebir aynı DNS mesajını** taşır.
Değişen tek şey, o mesajın içinden geçtiği **boru**:

```
Do53:  [DNS mesajı]  ->  çıplak UDP/TCP            (açık,    port 53)
DoT:   [DNS mesajı]  ->  TLS tüneli (TCP üstünde)  (şifreli, port 853)
DoH:   [DNS mesajı]  ->  HTTPS isteğinin gövdesi   (şifreli, port 443)
DoQ:   [DNS mesajı]  ->  QUIC stream'i (UDP üstü)  (şifreli, port 853/udp)
```

Çözümleme mantığı — root → TLD → authoritative sunucuları gezerek cevabı
kendisi bulan recursive motor — **hepsinde ortaktır**. Bu projede o motor
`DNSCore.resolve()`. Her protokol yalnızca şu dört adımı yapan ince bir
kabuktur:

```
1. Baytı kendi formatında AL
2. DNS mesajına PARSE et
3. Ortak motora ver:  DNSCore.resolve()
4. Cevabı kendi formatında GERİ YOLLA
```

Yani şifreleme "işin özü" değil; motorun etrafına geçirilen bir zarf.

---

## Do53 — Düz DNS

Klasik, şifresiz DNS. Diğerlerinin çıkış noktası budur.

- **Taşıma:** UDP (büyük/kesik cevaplarda TCP'ye düşer)
- **Port:** 53
- **Şifreleme:** yok
- **Çerçeveleme:** UDP'de ham DNS mesajı; TCP'de önüne **2 baytlık uzunluk**
  öneki eklenir
- **Standart:** RFC 1035 (DNS), RFC 7766 (TCP)
- **Artı:** her yerde çalışır, en basit, en hızlı el sıkışma (yok denecek kadar)
- **Eksi:** açık metin — gizlilik ve bütünlük yok

---

## DoH — DNS-over-HTTPS

DNS mesajını **bir HTTPS isteğinin içine** koyar.

- **Taşıma:** HTTP (genelde HTTP/2), TLS üstünde, TCP üstünde
- **Port:** 443 (yani normal web trafiğiyle aynı port)
- **DNS nasıl taşınır:** ham wire-format DNS mesajı, HTTP gövdesinde. `POST`
  (`Content-Type: application/dns-message`) ya da `GET` (base64url `dns`
  parametresi). Bu proje `POST /dns-query` kullanır.
- **Standart:** RFC 8484
- **Artı:** **normal HTTPS web trafiğine karışır** — bir gözlemci onu sıradan
  bir site ziyaretinden ayırt edemez, bu yüzden **engellenmesi en zor**
  yöntemdir. Reverse proxy / CDN / Cloudflare Tunnel arkasında çok rahat çalışır.
- **Eksi:** HTTP katmanının getirdiği fazladan yük; en "ağır" yöntem.

### DoH bir sorguda tam olarak ne olur?

DoH'ta istemci, DNS mesajını doğrudan ağa bırakmaz; önce bunu bir HTTP isteğinin
içine paketler. Tipik akış şöyledir:

1. İstemci 443 portuna TCP bağlantısı açar.
2. Ardından TLS el sıkışması başlar. Sunucu sertifikasını gönderir, istemci bu
  sertifikanın geçerli olup olmadığını doğrular.
3. Sertifika doğrulaması başarılıysa taraflar artık aynı oturuma ait simetrik
  anahtarları paylaşır. Bundan sonra gönderilen her HTTP baytı TLS ile
  şifrelenir.
4. İstemci DNS sorgusunu ham wire-format olarak hazırlayıp HTTP isteğinin
  gövdesine koyar. Bu projede kullanılan biçim `POST /dns-query` ve
  `Content-Type: application/dns-message` şeklindedir.
5. Sunucu TLS katmanında isteği çözer, HTTP gövdesinden DNS mesajını çıkarır,
  parse eder ve ortak çözümleme motoruna verir.
6. Motor cevabı üretir; sunucu bunu tekrar DNS wire-format'a çevirir ve HTTP
  response gövdesi olarak geri yollar.
7. İstemci cevabı TLS içinde alır, HTTP katmanından çıkarır ve DNS cevabını
  okur.

Buradaki kritik nokta şudur: dışarıdan bakan biri sadece sıradan bir HTTPS
trafik görür. DNS sorgusunun içeriği, kullanılan alan adı ve dönen cevap,
TLS tünelinin içinde kalır. Eğer sertifika doğrulaması başarısız olursa istemci
güvenlik nedeniyle bağlantıyı keser; yani "şifreledim ama kime şifreledim?" sorusunun
cevabı sertifika ile sabitlenmiş olur.

HTTP katmanı ayrıca bazı pratik avantajlar sağlar: aynı bağlantı üzerinde birden
fazla istek taşınabilir, cevaplar HTTP kurallarına göre yönetilir ve gerekirse
reverse proxy / CDN arkasında sonlandırma yapılabilir.

---

## DoT — DNS-over-TLS

DNS'i doğrudan bir **TLS tüneli** içinden geçirir.

- **Taşıma:** TLS, TCP üstünde
- **Port:** 853 (yalnızca DNS'e ayrılmış)
- **Çerçeveleme:** TCP DNS'iyle aynı — önüne **2 baytlık uzunluk** öneki, ama
  tünelin içinde şifreli
- **Standart:** RFC 7858
- **Artı:** DoH'tan basit, temiz bir ayrım; bağlantı yeniden kullanımıyla iyi
  performans.
- **Eksi:** kendine ait bir portta (853) durduğu için **"bu DNS trafiği" diye
  tanınması ve engellenmesi kolaydır** — DoH'un aksine web trafiğine karışmaz.

### DoT bir sorguda tam olarak ne olur?

DoT, DNS'i HTTP ile sarmalamaz; DNS mesajını daha doğrudan bir TLS oturumuna
yerleştirir. Akış kabaca şöyledir:

1. İstemci 853/tcp portuna bağlanır.
2. TCP bağlantısı kurulduktan sonra TLS ClientHello gider; istemci hangi TLS
  sürümlerini ve şifre takımlarını desteklediğini bildirir.
3. Sunucu ServerHello ile yanıt verir ve sertifikasını gönderir.
4. İstemci sertifikanın güvenilir bir otorite tarafından imzalanıp
  imzalanmadığını ve sunucu adıyla eşleşip eşleşmediğini doğrular.
5. El sıkışma tamamlandığında trafik artık TLS kayıtları içinde şifreli akar.
6. DNS sorgusu TCP akışı içinde, başında 2 baytlık uzunluk alanı olacak şekilde
  gönderilir. Bu uzunluk, alıcıya "bir sonraki DNS mesajı kaç bayt?" bilgisini
  verir.
7. Sunucu TLS katmanında veriyi çözer, uzunluk önekini okuyup DNS mesajını
  çıkarır, başlığı ve soru bölümünü parse eder.
8. Çözümleme motoru cevabı oluşturur; sunucu bunu yine 2 bayt uzunluk + DNS
  wire-format olarak paketler ve TLS ile geri yollar.
9. İstemci cevabı aldıktan sonra aynı bağlantıyı başka sorgular için de
  kullanabilir; bu yüzden bağlantı kurma maliyeti her sorguda tekrar ödenmez.

DoT'ta dikkat edilmesi gereken şey, şifrelemenin TCP bağlantısı kurulur kurulmaz
başlamasıdır; DNS mesajı doğrudan açık metin olarak ağda dolaşmaz. Aradaki ağ
cihazları sadece TCP oturumu ve TLS kayıtlarını görür, gerçek DNS içeriğini
göremez.

DoT'un yapısı DoH'tan daha sade, çünkü HTTP katmanı yoktur. Buna karşılık port
853 üzerinden çalıştığı için ağ politikaları tarafından DNS olarak daha kolay
tespit edilir.

---

## DoQ — DNS-over-QUIC

DNS'i **QUIC** üzerinden taşır. QUIC, TLS 1.3'ü içine gömmüş, UDP üstünde
çalışan modern bir transport protokolüdür (HTTP/3'ün de altındaki katman).

- **Taşıma:** QUIC (TLS 1.3 gömülü), UDP üstünde
- **Port:** 853 — ama **UDP** (DoT ile aynı numara, farklı protokol)
- **Çerçeveleme:** her DNS sorgusu **kendi QUIC stream'inde**, önünde 2 baytlık
  uzunluk. DNS mesaj ID'si **0** olur (çoğullamayı stream'ler sağladığı için ID
  gereksiz).
- **Standart:** RFC 9250
- **Artı:**
  - **Head-of-line blocking yok:** stream'ler bağımsız — bir sorgunun paketi
    kaybolsa diğer sorgular etkilenmez (TCP/DoT'ta bir kayıp arkasındaki her
    şeyi bekletir).
  - **Hızlı el sıkışma:** 1-RTT, tekrar bağlanışta 0-RTT.
  - **Bağlantı göçü:** IP değişse bile (Wi-Fi → mobil) bağlantı Connection ID
    ile kopmadan devam eder.
  - Şifreleme zorunlu.
- **Eksi:** en yeni yöntem, desteği en az yaygın olan; bazı ağlar UDP'yi
  kısıtlayabilir; bir QUIC kütüphanesi gerektirir (`aioquic`).

### DoQ bir sorguda tam olarak ne olur?

DoQ, DoT'a benzer şekilde şifreli DNS taşır ama TCP yerine UDP ve QUIC kullanır.
Buradaki temel fark, QUIC'in hem taşıma katmanı hem de güvenlik katmanını birlikte
sunmasıdır.

1. İstemci 853/udp portuna bir QUIC Initial paketi gönderir.
2. Bu ilk paket içinde TLS 1.3 tabanlı QUIC el sıkışmasının başlangıcı yer alır.
  Sunucu yine sertifikasını sunar ve istemci sertifikayı doğrular.
3. El sıkışma tamamlandığında QUIC bağlantısı kurulur. Artık veri, tek bir UDP
  akışı gibi görünse de QUIC stream'lerine bölünmüş, şifreli ve çoğullamalı
  şekilde taşınır.
4. Her DNS sorgusu ayrı bir QUIC stream içinde gönderilebilir. Bu sayede bir
  sorgu gecikse bile diğer sorgular aynı bağlantı içinde ilerlemeye devam eder.
5. DNS mesajı yine wire-format olarak taşınır; sunucu stream'i açar, veriyi
  çözer, DNS paketini parse eder ve çözümleme motoruna verir.
6. Cevap aynı stream üzerinden geri gönderilir. İstemci cevabı aldığında DNS
  mesajını normal bir DNS response gibi işler.
7. Bağlantı devam ederse aynı QUIC oturumu üzerinde yeni sorgular çok daha düşük
  ek maliyetle gönderilebilir. Mobil ağ değişimi gibi durumlarda Connection ID
  sayesinde oturumun sürmesi de mümkündür.

DoQ'nun önemli avantajı, paket kaybı olduğunda TCP gibi bütün akışı bekletmemesidir.
Bu, özellikle aynı anda çok sayıda sorgu yapan istemcilerde hissedilir. Buna
karşılık QUIC, UDP kullandığı için bazı ağlarda daha kolay filtrelenebilir.

Pratikte DoQ akışı şu fikre indirgenebilir: "önce QUIC ile güvenli bir yol
kur, sonra DNS mesajlarını o yolun stream'lerinden geçir." Bu yüzden TLS, DNS'in
üstüne sonradan eklenen bir katman değil; QUIC'in içine gömülü bir parça olarak
çalışır.

---

## Karşılaştırma tablosu

| Özellik            | Do53         | DoT          | DoH              | DoQ                |
|--------------------|--------------|--------------|------------------|--------------------|
| Alt taşıma         | UDP/TCP      | TCP          | TCP (HTTP)       | UDP (QUIC)         |
| Şifreleme          | ❌ yok       | ✅ TLS       | ✅ TLS           | ✅ TLS 1.3 (gömülü)|
| Port               | 53           | 853          | 443              | 853/udp            |
| Sertifika gerekir  | Hayır        | Evet         | Evet¹            | Evet               |
| Web trafiğine karışır | —         | Hayır        | **Evet**         | Hayır              |
| Engellenme kolaylığı | Çok kolay  | Kolay (port) | **Zor**          | Orta (UDP)         |
| HOL blocking       | —            | Var          | Var              | **Yok**            |
| El sıkışma hızı    | En hızlı     | Orta         | En yavaş         | Hızlı (0/1-RTT)    |
| Standart           | RFC 1035     | RFC 7858     | RFC 8484         | RFC 9250           |

¹ Bu projede DoH, sertifika yoksa **düz HTTP**'ye düşer (önünde TLS sonlandıran
bir proxy — örn. Cloudflare Tunnel — varsa güvenlidir).

---

## Bu projede nasıl uygulandı

Mimari, "ortak motor + protokol başına ince kabuk" fikri üzerine kuruludur:

| Katman | Dosya | Rol |
|--------|-------|-----|
| **Motor** | `servers/normal_udp.py` (`DNSCore`) | Recursive çözümleme — hepsi paylaşır |
| Do53   | `servers/normal_udp.py` (`DNSResolver`) | UDP/TCP, `dnslib` |
| DoH    | `servers/https_server.py` | `http.server` + `ssl`, `POST /dns-query` |
| DoT    | `servers/dot_server.py`   | `dnslib` DNSServer (TCP) + `ssl.wrap_socket` |
| DoQ    | `servers/doq_server.py`   | `aioquic` (async) |
| Orkestratör | `app.py` | `SERVER_REGISTRY`, sunucuları başlatıp durdurur |

Her sunucu `ENABLE_*_SERVER` ortam değişkeniyle açılıp kapatılır ve **tek bir
`DNSCore`'u** paylaşır. Bir önemli fark:

- **Do53 / DoH / DoT** thread'lerde çalışır (`loop.run_in_executor`).
- **DoQ** asenkron'dur (`aioquic`), event loop'un üstünde bir task olarak
  çalışır. Bu yüzden DoQ handler'ında çözümleme `run_in_executor` ile ayrı bir
  thread'e atılır — yoksa senkron `resolve()` çağrısı tüm event loop'u bloklardı.

### Portlar (bu proje)

| Protokol | Container portu | Dış (host) port | Ortam değişkeni |
|----------|-----------------|-----------------|-----------------|
| Do53     | 5300            | 53              | `CONTAINER_UDP_PORT`   |
| DoH      | 44300           | 443             | `CONTAINER_HTTPS_PORT` |
| DoT      | 8853            | 853/tcp         | `CONTAINER_DOT_PORT`   |
| DoQ      | 8530            | 853/udp         | `CONTAINER_DOQ_PORT`   |

Container portları 1024'ün üstünde seçilmiştir ki root olmayan container
kullanıcısı bağlayabilsin; ayrıcalıklı dış portlar (53/443/853) Docker host
tarafında eşlenir.

### Sertifikalar

DoH, DoT ve DoQ **TLS sertifikası ister** (`CERT_FILE` / `KEY_FILE`). Do53
istemez.

- **DoH:** sertifika yoksa düz HTTP olarak başlar (reverse proxy senaryosu).
- **DoT / DoQ:** TLS zorunlu olduğu için sertifika yoksa **başlamaz** (uyarı
  basıp atlanır).

---

## Hangisini kullanmalı?

- **Engellemeyi/DPI'ı aşmak, maksimum gizlilik:** **DoH** — web trafiğine
  karıştığı için ayırt edilmesi en zor.
- **Temiz, basit, düşük gecikmeli şifreli DNS:** **DoT** — ağın 853'ü
  engellemiyorsa idealdir.
- **En modern, düşük gecikme, mobilde bağlantı göçü:** **DoQ** — desteği
  yaygınlaştıkça en iyi seçenek; ağ UDP'ye izin veriyorsa.
- **İç ağ, güvenilir ortam, sıfır ek yük:** **Do53** — şifrelemeye gerek yoksa.

Hepsi aynı anda açık olabilir; istemci hangisini desteklerse onu kullanır.
