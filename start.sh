#!/usr/bin/env bash
#
# Dns Python baslatici.
# config/servers.json'u okur -> host'a yayinlanacak portlar icin
# docker-compose.override.yml uretir -> docker compose up -d --build.
#
# config/servers.json'daki 'enabled' (aç/kapa) ve 'container_port' degisimleri
# ZATEN CANLI uygulanir (resolver ~5 sn'de). Bu script yalniz HOST'A YAYIN
# (publish/external_port/site_port) degistiginde ya da ilk kurulumda gerekir
# (Docker port eslemesi container recreate ister).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
CONFIG_DIR="config"
CONFIG_PATH="$CONFIG_DIR/servers.json"
EXAMPLE_PATH="$CONFIG_DIR/servers.example.json"
OVERRIDE_PATH="docker-compose.override.yml"
PY="$(command -v python3 || command -v python)"

# config yoksa ornekten olustur
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_PATH" ]; then
    if [ -f "$EXAMPLE_PATH" ]; then
        cp "$EXAMPLE_PATH" "$CONFIG_PATH"
        echo "[start] $CONFIG_PATH yok -> ornekten olusturuldu (once ./setup.sh onerilir)."
    else
        echo "[start] HATA: $CONFIG_PATH yok ve ornek de bulunamadi." >&2
        exit 1
    fi
fi

# servers.json -> docker-compose.override.yml (+ ekranda ozet)
CONFIG_PATH="$CONFIG_PATH" OVERRIDE_PATH="$OVERRIDE_PATH" "$PY" - <<'PY'
import json, os

cfg = json.load(open(os.environ["CONFIG_PATH"]))
site = int(cfg.get("site_port", 8444))
methods = cfg.get("methods", {})

# metot -> yayinlanacak (proto listesi)
PROTO = {"udp": ["udp", "tcp"], "doh": ["tcp"], "dot": ["tcp"], "doq": ["udp"]}

lines = []
# Panel: yalniz 127.0.0.1 (SSH tunel / yerel; public DEGIL)
lines.append(f'      - "127.0.0.1:{site}:{site}"')
published = []
for name in ("udp", "doh", "dot", "doq"):
    m = methods.get(name, {})
    if not m.get("publish"):
        continue
    cp, ep = int(m["container_port"]), int(m["external_port"])
    for proto in PROTO[name]:
        lines.append(f'      - "{ep}:{cp}/{proto}"')
    published.append(f"{name}({ep}->{cp})")

override = (
    "# start.sh tarafindan config/servers.json'dan URETILDI — elle duzenleme.\n"
    "# git ile izlenmez. Portu degistirmek icin: panel ya da ./setup.sh + ./start.sh.\n"
    "services:\n"
    "  dns-python:\n"
    "    ports:\n" + "\n".join(lines) + "\n"
)
with open(os.environ["OVERRIDE_PATH"], "w") as f:
    f.write(override)

print(f"[start] {os.environ['OVERRIDE_PATH']} yazildi.")
print(f"[start] Panel yayini: 127.0.0.1:{site}")
print(f"[start] Host'a yayinlanan DNS metotlari: {', '.join(published) if published else '(yok — sadece dns-net/tunel)'}")
enabled = [n for n in ('udp','doh','dot','doq') if methods.get(n, {}).get('enabled')]
print(f"[start] Acik metotlar (resolver): {', '.join(enabled) if enabled else '(yok)'}")
PY

echo "[start] docker compose up -d --build ..."
if docker compose up -d --build; then
    echo "[start] Baslatildi. Panel: http://127.0.0.1:$("$PY" -c "import json;print(json.load(open('$CONFIG_PATH'))['site_port'])")"
else
    echo "[start] HATA: docker compose baslatilamadi (izin/daemon?). Elle: docker compose up -d --build" >&2
    exit 1
fi
