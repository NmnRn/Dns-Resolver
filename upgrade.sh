#!/usr/bin/env bash
#
# Repo'yu GitHub'dan gunceller. docker-compose.yml / Dockerfile gibi genelde
# elle ozellestirilen dosyalarda upstream'de degisiklik varsa, uzerine
# yazmadan once sorar.
#
# Calistirmak icin: ./upgrade.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Elle ozellestirilmesi beklenen, uzerine yazmadan once sorulacak dosyalar.
SENSITIVE_FILES=(docker-compose.yml Dockerfile)

if [ -n "$(git status --porcelain)" ]; then
    echo "Commit edilmemis degisiklikler var, once onlari commit'le ya da stash'le." >&2
    git status --short >&2
    exit 1
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
echo "Guncellemeler kontrol ediliyor (origin/$BRANCH)..."
git fetch origin "$BRANCH"

if git diff --quiet HEAD "origin/$BRANCH"; then
    echo "Zaten guncelsin, yapilacak bir sey yok."
    exit 0
fi

echo
echo "Degisen dosyalar:"
git diff --name-only HEAD "origin/$BRANCH" | sed 's/^/  - /'
echo

KEEP_LOCAL=()
BACKUP_DIR="$(mktemp -d)"
trap 'rm -rf "$BACKUP_DIR"' EXIT

for f in "${SENSITIVE_FILES[@]}"; do
    [ -f "$f" ] || continue
    if ! git diff --quiet HEAD "origin/$BRANCH" -- "$f"; then
        echo "=== $f upstream'de degismis ==="
        git diff HEAD "origin/$BRANCH" -- "$f" || true
        echo
        read -r -p "Bu dosya guncellensin mi? (kendi ayarlarini kaybetmek istemiyorsan hayir de) (e/h) [h]: " ans
        case "${ans:-h}" in
            e|E|evet|Evet|y|Y|yes)
                echo "-> $f guncellenecek."
                ;;
            *)
                echo "-> $f oldugu gibi korunacak."
                cp "$f" "$BACKUP_DIR/$(basename "$f")"
                KEEP_LOCAL+=("$f")
                ;;
        esac
        echo
    fi
done

echo "Degisiklikler birlestiriliyor..."
git merge --no-edit "origin/$BRANCH"

for f in "${KEEP_LOCAL[@]:-}"; do
    [ -z "$f" ] && continue
    cp "$BACKUP_DIR/$(basename "$f")" "$f"
    echo "$f: yerel (eski) halin geri yuklendi, upstream degisikligi alinmadi."
done

if [ "${#KEEP_LOCAL[@]}" -gt 0 ]; then
    echo
    echo "Not: korudugun dosyalar (${KEEP_LOCAL[*]}) commit edilmedi, calisma"
    echo "dizininde degisiklik olarak duruyor - istersen kendin commit'le."
fi

echo
echo "Guncelleme tamamlandi."
