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
