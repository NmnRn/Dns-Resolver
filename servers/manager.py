"""
DNS sunucularını ÇALIŞIRKEN (restart'sız) yöneten reconcile yöneticisi.

`config_store` (config/servers.json — istenen durum) periyodik okunur ve fiili
durumla karşılaştırılır: istenip çalışmayan metot başlatılır, çalışıp istenmeyen
durdurulur, açık ama **container portu değişen** metot yeniden başlatılır. Böylece
web panelinden bir metodu açıp kapatmak (ya da iç portunu değiştirmek), konteyneri
yeniden başlatmadan ~birkaç saniyede etki eder. (Host'a YAYINLANAN dış port
değişimi Docker gereği recreate ister → start.sh.)

`get_desired`: SENKRON bir callable; {method: {"enabled": bool, "container_port": int}}
döndürür (config_store dosya-cache'inden okur — mtime değişmediyse diske gitmez).

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
        # method -> (stop(), container_port) (çalışan sunucular)
        self.running: dict[str, tuple] = {}
        # istenip başlatılamayanlar (cert yok vb.) — her açma kenarında bir kez denenir,
        # her turda tekrar deneyip log'u boğmamak için.
        self.failed: set[str] = set()

    async def reconcile_loop(self, get_desired, interval: float = 5) -> None:
        """İstenen durumu periyodik okuyup fiili durumu ona sürekli yaklaştırır.
        get_desired SENKRONdur (config_store)."""
        while True:
            try:
                await self.reconcile(get_desired())
            except Exception as e:
                logger.error("reconcile döngüsü hatası: %r", e)
            await asyncio.sleep(interval)

    async def reconcile(self, desired: dict) -> None:
        """desired = {method: {"enabled": bool, "container_port": int}} (ya da geriye
        dönük {method: bool}). Fiili durumu istenen duruma yaklaştırır."""
        for method, spec in desired.items():
            if method not in self.starters:
                continue
            if isinstance(spec, dict):
                want = bool(spec.get("enabled"))
                port = spec.get("container_port")
            else:                                   # geriye dönük: düz bool
                want, port = bool(spec), None
            entry = self.running.get(method)        # (stop, port) | None
            running = entry is not None
            if want and not running and method not in self.failed:
                await self._start(method, port)
            elif want and running and port is not None and entry[1] != port:
                logger.info("%s iç portu değişti (%s→%s), yeniden başlatılıyor.",
                            method, entry[1], port)
                await self._stop(method)
                await self._start(method, port)
            elif not want and running:
                await self._stop(method)
            elif not want:
                # istenmeyen bir metot; başarısız işaretini temizle (yeni açmada tekrar dene)
                self.failed.discard(method)

    async def _start(self, method: str, port=None) -> None:
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
        self.running[method] = (stop, port)
        self.failed.discard(method)
        logger.info("%s sunucusu çalışırken başlatıldı (port=%s).", method, port)

    async def _stop(self, method: str) -> None:
        entry = self.running.pop(method, None)
        if entry is None:
            return
        stop = entry[0]
        try:
            stop()
        except Exception as e:
            logger.error("%s durdurulurken hata: %r", method, e)
        else:
            logger.info("%s sunucusu çalışırken durduruldu.", method)

    def stop_all(self) -> None:
        """Kapanışta tüm çalışan sunucuları durdurur."""
        for method, (stop, _port) in list(self.running.items()):
            try:
                stop()
            except Exception as e:
                logger.error("%s durdurulurken hata: %r", method, e)
        self.running.clear()
