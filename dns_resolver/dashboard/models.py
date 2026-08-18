from django.db import models


class PanelLogin(models.Model):
    """Web panele BAŞARILI her giriş — cihaz/erişim denetim kaydı (audit).

    Django auth User'dan bağımsızdır (username string olarak saklanır) → kullanıcı
    silinse bile kayıt korunur. Django'nun SQLite'ında yaşar (auth ile birlikte);
    DNS sorgu verisi ise MariaDB'dedir. Panel 'Cihazlar' sayfasını besler.
    """
    username = models.CharField(max_length=150)
    ip = models.CharField(max_length=64, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.username}@{self.ip}'


class DeviceProfile(models.Model):
    """Panele erişen benzersiz cihaz. Kimlik = istemcinin <b>localStorage</b>'daki
    kalıcı id'si (farble-proof, oturumlar arası sabit; tarayıcı bunu rastgelemez);
    localStorage kapalıysa oturum-içi fallback id. Aynı cihaz her açılışta/beacon'da
    YENİ satır yerine BU satırı günceller. fingerprint alanları betimleyicidir; açılışlar
    arası DEĞİŞEN alanlar `volatile`'a düşer (tarayıcı onları rastgeliyor). Görülen tüm
    IP'ler `ips`'te (VPN/ağ değişimi burada görünür)."""
    fp_hash = models.CharField(max_length=64, unique=True, db_index=True)  # = istemci kimliği (düz)
    # PII/tanımlayıcı alanlar at-rest ŞİFRELİ saklanır (logcrypto/AES-SIV, DNS_LOG_KEY;
    # anahtar yoksa düz). Şifreli değer 'enc:<b64>' → sabit boydan taşar diye TextField.
    ip = models.TextField(blank=True)                                      # son görülen IP (şifreli)
    ips = models.TextField(blank=True)                                     # görülen tüm IP'ler (şifreli)
    volatile = models.CharField(max_length=200, blank=True)                # oynak/rastgeleşen alanlar (düz)
    user_agent = models.TextField(blank=True)                              # (şifreli)
    browser = models.CharField(max_length=40, blank=True)                  # kaba etiket (düz)
    os = models.CharField(max_length=40, blank=True)
    device = models.CharField(max_length=20, blank=True)
    # istemci (JS) tarafı fingerprint alanları — tanımlayıcılar ŞİFRELİ (TextField)
    screen = models.TextField(blank=True)
    viewport = models.TextField(blank=True)
    timezone = models.TextField(blank=True)
    platform = models.TextField(blank=True)
    languages = models.TextField(blank=True)
    color_depth = models.CharField(max_length=8, blank=True)               # düşük entropi → düz
    cpu = models.CharField(max_length=8, blank=True)                       # farble/düşük → düz
    memory = models.CharField(max_length=8, blank=True)
    gpu = models.TextField(blank=True)
    touch = models.BooleanField(default=False)
    canvas_hash = models.TextField(blank=True)
    # Fingerprint koruması: Brave/Tor/Firefox-RFP canvas'ı her okumada
    # rastgeleleştirir (farbling) → canvas dedup anahtarından ÇIKARILIR.
    brave = models.BooleanField(default=False)
    fp_protected = models.BooleanField(default=False)
    extra = models.TextField(blank=True)          # ham fingerprint JSON (detay)
    username = models.CharField(max_length=150, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(db_index=True)
    hits = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ['-last_seen']

    def __str__(self):
        return f'{self.browser}/{self.os}@{self.ip}'
