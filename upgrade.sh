#!/usr/bin/env bash
#
# Kurulu surumu GitHub'dan gunceller.
#
# Yalnizca git ile IZLENEN (tracked) dosyalari gunceller: kod (app.py,
# servers/, db_ops/ ...), Dockerfile, docker-compose.yml. Senin YEREL
# dosyalarina — .env, config/servers.json, docker-compose.override.yml,
# certificates/ — HIC dokunmaz; bunlar git tarafindan gormezden gelindigi
# icin (.gitignore) guncelleme sirasinda oldugu gibi korunur.
#
# Calistirmak icin: ./upgrade.sh  (ya da: bash upgrade.sh)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
echo "Guncellemeler kontrol ediliyor (origin/$BRANCH)..."
git fetch --quiet origin "$BRANCH"

if git diff --quiet HEAD "origin/$BRANCH"; then
    echo "Zaten guncelsin, yapilacak bir sey yok."
    exit 0
fi

# Izlenen dosyalarda elle yapilmis degisiklik var mi? (untracked haric)
# Varsa reset --hard onlari kaybederdi; once uyarip duruyoruz.
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "UYARI: izlenen dosyalarda yerel degisiklik var:" >&2
    git status --short --untracked-files=no >&2
    echo >&2
    echo "Guncelleme bunlari ustune yazardi. Once geri al (git checkout -- <dosya>)" >&2
    echo "ya da baska yere kaydet, sonra tekrar dene." >&2
    exit 1
fi

echo
echo "Guncellenecek dosyalar:"
git diff --name-only HEAD "origin/$BRANCH" | sed 's/^/  - /'
echo

# Izlenen dosyalari origin/$BRANCH haline getir. `reset --hard` UNTRACKED
# dosyalara (.env, docker-compose.override.yml, certificates/*) DOKUNMAZ —
# yerel ayarlarin ve sertifikalarin korunur.
git reset --hard "origin/$BRANCH"
echo "Kod guncellendi."

# Kod degisti ama calisan container hala eski imaji kullaniyor; degisikliklerin
# etkin olmasi icin yeniden build + start gerekir.
if [ -f docker-compose.yml ] && command -v docker >/dev/null; then
    read -r -p "Container yeniden build edilip baslatilsin mi? (e/h) [e]: " ans
    case "${ans:-e}" in
        e|E|evet|Evet|y|Y|yes)
            docker compose up -d --build
            ;;
        *)
            echo "Atlandi. Degisikliklerin etkin olmasi icin: docker compose up -d --build"
            ;;
    esac
fi

echo
echo "Guncelleme tamamlandi."
