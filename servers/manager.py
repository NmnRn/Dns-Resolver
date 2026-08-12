"""
DNS sunucularını ÇALIŞIRKEN (restart'sız) yöneten reconcile yöneticisi.

DB'deki `resolver_config` (istenen durum) periyodik okunur ve fiili durumla
karşılaştırılır: istenip çalışmayan metot başlatılır, çalışıp istenmeyen durdurulur.
Böylece web panelinden bir metodu açıp kapatmak, konteyneri/prosesi yeniden
başlatmadan anında etki eder.

Her metot bir "starter" ile temsil edilir: çağrıldığında sunucuyu başlatıp bir
`stop()` fonksiyonu döndüren async fonksiyon; başlatılamazsa (ör. DoT/DoQ için
sertifika yok) None döndürür.
"""
import asyncio

from logs.dns_logs import logger


class ServerManager:
    def __init__(self, starters: dict):
        # method -> async starter() -> stop() | None
        self.starters = starters
        # method -> stop() (çalışan sunucular)
        self.running: dict[str, callable] = {}
        # istenip başlatılamayanlar (cert yok vb.) — her açma kenarında bir kez denenir,
        # her turda tekrar deneyip log'u boğmamak için.
        self.failed: set[str] = set()

    async def reconcile_loop(self, get_config, interval: float = 5) -> None:
        """DB'yi periyodik okuyup fiili durumu istenen duruma sürekli yaklaştırır."""
        while True:
            try:
                desired = await get_config()
                await self.reconcile(desired)
            except Exception as e:
                logger.error("reconcile döngüsü hatası: %r", e)
            await asyncio.sleep(interval)

    async def reconcile(self, desired: dict) -> None:
        """desired = {method: bool}. Fiili durumu istenen duruma yaklaştırır."""
        for method, want in desired.items():
            if method not in self.starters:
                continue
            running = method in self.running
            if want and not running and method not in self.failed:
                await self._start(method)
            elif not want and running:
                await self._stop(method)
            elif not want:
                # istenmeyen bir metot; başarısız işaretini temizle (yeni açmada tekrar dene)
                self.failed.discard(method)

    async def _start(self, method: str) -> None:
        try:
            stop = await self.starters[method]()
        except Exception as e:
            logger.error("%s başlatılırken hata: %r", method, e)
            self.failed.add(method)
            return
        if stop is None:
            # Ön koşul yok (ör. sertifika) — istenip başlatılamadı. Bir kez işaretle.
            logger.warning("%s açık isteniyor ama başlatılamadı (ör. sertifika yok).", method)
            self.failed.add(method)
            return
        self.running[method] = stop
        self.failed.discard(method)
        logger.info("%s sunucusu çalışırken başlatıldı.", method)

    async def _stop(self, method: str) -> None:
        stop = self.running.pop(method, None)
        if stop is None:
            return
        try:
            stop()
        except Exception as e:
            logger.error("%s durdurulurken hata: %r", method, e)
        else:
            logger.info("%s sunucusu çalışırken durduruldu.", method)

    def stop_all(self) -> None:
        """Kapanışta tüm çalışan sunucuları durdurur."""
        for method, stop in list(self.running.items()):
            try:
                stop()
            except Exception as e:
                logger.error("%s durdurulurken hata: %r", method, e)
        self.running.clear()
