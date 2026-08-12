#!/usr/bin/env python
"""
Tek container içinde İKİ AYRI process çalıştırır:

  1) DNS resolver -> python app.py                      (cwd: /app)
  2) Web sitesi   -> uvicorn (ASGI Django, ayrı port)   (cwd: /app/dns_resolver)

İki process tamamen ayrıdır; birbirini import etmez, yalnızca paylaşılan MariaDB
(dns_cache tablosu) üzerinden buluşurlar. Bu launcher:
  - başlangıçta Django'nun kendi SQLite şemasını migrate eder,
  - iki process'i başlatır,
  - SIGTERM/SIGINT'i her ikisine iletir (resolver DB tamponunu boşaltabilsin),
  - biri durursa diğerini de kapatıp aynı çıkış koduyla çıkar
    (compose 'restart: unless-stopped' konteyneri yeniden başlatır).

Not: process'lerin BAĞIMSIZ yeniden başlatılması istenirse supervisord'a geçilir;
burada kasıtlı olarak "biri ölürse konteyner yeniden başlar" davranışı seçildi.
"""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DJANGO_DIR = BASE_DIR / "dns_resolver"
PYTHON = sys.executable

SITE_BIND = os.getenv("SITE_BIND", "0.0.0.0")
SITE_PORT = os.getenv("SITE_PORT", "8444")

# (isim, Popen) çiftleri
procs: list[tuple[str, subprocess.Popen]] = []
_stopping = False


def _spawn(name: str, args: list[str], cwd: Path) -> None:
    print(f"[launcher] {name} başlatılıyor: {' '.join(args)} (cwd={cwd})", flush=True)
    procs.append((name, subprocess.Popen(args, cwd=str(cwd))))


def _terminate_all() -> None:
    for name, p in procs:
        if p.poll() is None:
            print(f"[launcher] {name} -> SIGTERM", flush=True)
            try:
                p.terminate()
            except ProcessLookupError:
                pass


def _handle_signal(signum, frame) -> None:
    global _stopping
    _stopping = True
    print(f"[launcher] sinyal {signum} alındı, process'ler durduruluyor...", flush=True)
    _terminate_all()


def main() -> None:
    # 1) Django'nun iç tablolarını (SQLite: auth/session/admin) hazırla.
    print("[launcher] Django migrate...", flush=True)
    subprocess.run([PYTHON, "manage.py", "migrate", "--noinput"], cwd=str(DJANGO_DIR), check=True)

    # 2) Sinyalleri her iki child'a ilet.
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # 3) İki process'i başlat.
    _spawn("resolver", [PYTHON, "app.py"], cwd=BASE_DIR)
    _spawn(
        "website",
        [PYTHON, "-m", "uvicorn", "dns_resolver.asgi:application",
         "--host", SITE_BIND, "--port", SITE_PORT],
        cwd=DJANGO_DIR,
    )

    # 4) Biri ölene (ya da sinyal gelene) kadar bekle.
    dead_name = None
    dead_code = 0
    while True:
        alive = False
        for name, p in procs:
            code = p.poll()
            if code is not None and dead_name is None:
                dead_name, dead_code = name, code
            alive = alive or (code is None)
        if dead_name is not None or not alive:
            break
        time.sleep(1)

    if _stopping:
        print(f"[launcher] planlı kapanma tamamlanıyor ({dead_name} durdu).", flush=True)
        exit_code = 0
    else:
        print(f"[launcher] {dead_name} beklenmedik şekilde durdu (exit={dead_code}). "
              f"Diğer process kapatılıyor, konteyner yeniden başlayacak.", flush=True)
        exit_code = dead_code or 1

    # 5) Kalanları kapat.
    _terminate_all()
    for name, p in procs:
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print(f"[launcher] {name} zamanında kapanmadı -> SIGKILL", flush=True)
            p.kill()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
