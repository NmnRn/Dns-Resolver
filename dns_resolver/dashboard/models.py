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
    """Panele erişen benzersiz cihaz — her sayfa açılışında JS ile toplanan
    tarayıcı fingerprint'i (ekran/tz/platform/GPU/canvas...). Dedup: aynı
    fp_hash (IP + UA + fingerprint alanları) varsa YENİSİ yazılmaz, yalnız
    last_seen/hits güncellenir. 'Cihaz Özellikleri' sayfasını besler."""
    fp_hash = models.CharField(max_length=64, unique=True, db_index=True)
    ip = models.CharField(max_length=64, blank=True)
    user_agent = models.TextField(blank=True)
    browser = models.CharField(max_length=40, blank=True)
    os = models.CharField(max_length=40, blank=True)
    device = models.CharField(max_length=20, blank=True)
    # istemci (JS) tarafı fingerprint alanları
    screen = models.CharField(max_length=40, blank=True)
    viewport = models.CharField(max_length=40, blank=True)
    timezone = models.CharField(max_length=64, blank=True)
    platform = models.CharField(max_length=64, blank=True)
    languages = models.CharField(max_length=128, blank=True)
    color_depth = models.CharField(max_length=8, blank=True)
    cpu = models.CharField(max_length=8, blank=True)
    memory = models.CharField(max_length=8, blank=True)
    gpu = models.CharField(max_length=200, blank=True)
    touch = models.BooleanField(default=False)
    canvas_hash = models.CharField(max_length=64, blank=True)
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
