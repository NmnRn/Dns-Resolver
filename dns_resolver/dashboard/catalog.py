"""
Hazır engelleme listesi kataloğu (AdGuard/Pi-hole tarzı).

Kullanıcı bu listelerden seçer → panel `blocklist_sources` tablosuna ekler →
resolver URL'yi indirip RAM'e yükler. Liste kaldırılırsa RAM'den de düşer.
URL'ler jsdelivr/raw.githubusercontent üzerinden çekilir; kırık bir URL panelde
'0 domain' olarak görünür ve silinebilir.
"""

# (name, url, category)
CATALOG = [
    # --- Genel (reklam + izleyici + kötücül karışık) ---
    ("StevenBlack Unified",        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "Genel"),
    ("OISD Small",                 "https://small.oisd.nl/", "Genel"),
    ("OISD Big",                   "https://big.oisd.nl/", "Genel"),
    ("AdGuard DNS filter",         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "Genel"),
    ("1Hosts (Lite)",              "https://cdn.jsdelivr.net/gh/badmojr/1Hosts@latest/Lite/adblock.txt", "Genel"),
    ("1Hosts (Pro)",               "https://cdn.jsdelivr.net/gh/badmojr/1Hosts@latest/Pro/adblock.txt", "Genel"),
    ("AdAway",                     "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt", "Genel"),
    ("Dan Pollock (someonewhocares)", "https://someonewhocares.org/hosts/zero/hosts", "Genel"),

    # --- Reklam / İzleyici ---
    ("Peter Lowe (Adservers)",     "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", "Reklam/İzleyici"),
    ("Frogeye First-party",        "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt", "Reklam/İzleyici"),
    ("WindowsSpyBlocker",          "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", "Reklam/İzleyici"),
    ("Lightswitch05 Ads+İzleyici", "https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/ads-and-tracking-extended.txt", "Reklam/İzleyici"),
    ("Frogeye Multiparty",         "https://hostfiles.frogeye.fr/multiparty-trackers-hosts.txt", "Reklam/İzleyici"),

    # --- Kötücül / Phishing (güvenlik) ---
    ("URLhaus (malware)",          "https://urlhaus.abuse.ch/downloads/hostfile/", "Güvenlik"),
    ("Phishing Army (Extended)",   "https://phishing.army/download/phishing_army_blocklist_extended.txt", "Güvenlik"),
    ("abuse.ch ThreatFox",         "https://threatfox.abuse.ch/downloads/hostfile/", "Güvenlik"),
    ("URLhaus Filter (curben)",    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt", "Güvenlik"),
    ("NoCoin (kripto madenci)",    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", "Güvenlik"),

    # --- Yetişkin / NSFW ---
    ("OISD NSFW",                  "https://nsfw.oisd.nl/", "Yetişkin"),
    ("StevenBlack + Porn",         "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts", "Yetişkin"),

    # --- Cihaz (Smart TV / mobil / yerel izleyiciler) ---
    ("Perflyst Smart TV",          "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt", "Cihaz"),
    ("Perflyst Android İzleyici",  "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt", "Cihaz"),

    # --- Kategorik (kumar / sosyal / sahte haber / bypass) ---
    ("StevenBlack Kumar",          "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts", "Kategorik"),
    ("StevenBlack Sosyal Medya",   "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts", "Kategorik"),
    ("StevenBlack Sahte Haber",    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts", "Kategorik"),
]

# name -> url (panelden 'katalogdan ekle' seçimi için hızlı arama)
CATALOG_BY_NAME = {name: url for name, url, _cat in CATALOG}


def catalog_grouped():
    """Kategoriye göre gruplu liste: [(kategori, [(name, url), ...]), ...]."""
    groups: dict[str, list] = {}
    for name, url, cat in CATALOG:
        groups.setdefault(cat, []).append((name, url))
    return list(groups.items())
