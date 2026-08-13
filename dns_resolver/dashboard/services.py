"""Ön tanımlı servis engelleme kataloğu (AdGuard "Blocked Services" tarzı).

Her servis, engellendiğinde DB'ye yazılacak alan adı kümesidir. Bir alanı engellemek
alt alanlarını da engeller (resolver'da parent-walk), o yüzden ağırlıklı olarak ana
alan adları yeterli. `id` panelde toggle için; `name` DB'de + attribution'da kullanılır.
"""

SERVICES = {
    "youtube":   {"name": "YouTube",   "domains": ["youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtubei.googleapis.com", "yt3.ggpht.com"]},
    "tiktok":    {"name": "TikTok",    "domains": ["tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "musical.ly", "ibytedtos.com"]},
    "instagram": {"name": "Instagram", "domains": ["instagram.com", "cdninstagram.com", "ig.me"]},
    "facebook":  {"name": "Facebook",  "domains": ["facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "fb.me"]},
    "x":         {"name": "X (Twitter)", "domains": ["twitter.com", "x.com", "twimg.com", "t.co", "twttr.com"]},
    "whatsapp":  {"name": "WhatsApp",  "domains": ["whatsapp.com", "whatsapp.net", "wa.me"]},
    "snapchat":  {"name": "Snapchat",  "domains": ["snapchat.com", "sc-cdn.net", "snap.com", "snapkit.com"]},
    "reddit":    {"name": "Reddit",    "domains": ["reddit.com", "redd.it", "redditstatic.com", "redditmedia.com"]},
    "netflix":   {"name": "Netflix",   "domains": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"]},
    "twitch":    {"name": "Twitch",    "domains": ["twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net"]},
    "discord":   {"name": "Discord",   "domains": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"]},
    "telegram":  {"name": "Telegram",  "domains": ["telegram.org", "telegram.me", "t.me", "telegra.ph", "tdesktop.com"]},
    "spotify":   {"name": "Spotify",   "domains": ["spotify.com", "scdn.co", "spotifycdn.com", "spoti.fi"]},
    "pinterest": {"name": "Pinterest", "domains": ["pinterest.com", "pinimg.com", "pin.it"]},
    "linkedin":  {"name": "LinkedIn",  "domains": ["linkedin.com", "licdn.com", "lnkd.in"]},
    "roblox":    {"name": "Roblox",    "domains": ["roblox.com", "rbxcdn.com", "roblox.co"]},
    "steam":     {"name": "Steam",     "domains": ["steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com"]},
    "9gag":      {"name": "9GAG",      "domains": ["9gag.com", "9cache.com"]},
}


def services_list():
    """Panel gösterimi için [(id, name)] — ada göre sıralı."""
    return sorted(((sid, s["name"]) for sid, s in SERVICES.items()), key=lambda x: x[1].lower())


# İçerik kategorileri (ebeveyn/kategori engelleme) — hazır blocklist kaynağı olarak
# eklenir/çıkarılır (mevcut abonelik altyapısını kullanır). "Yetişkin" + Güvenli Arama
# birlikte ebeveyn kontrolü sağlar.
CATEGORIES = {
    "adult":    {"name": "Yetişkin İçerik",     "url": "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts"},
    "gambling": {"name": "Kumar",               "url": "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/gambling-hosts"},
    "social":   {"name": "Sosyal Medya",        "url": "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/social-hosts"},
    "violence": {"name": "Şiddet / Uyuşturucu", "url": "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/snuff-hosts"},
}


def categories_list():
    return [(cid, c["name"], c["url"]) for cid, c in CATEGORIES.items()]


# Güvenli arama motorları (id resolver'daki SAFE_SEARCH_ENGINES ile aynı olmalı).
SAFESEARCH_ENGINES = [
    ("google", "Google"), ("youtube", "YouTube"), ("bing", "Bing"),
    ("duckduckgo", "DuckDuckGo"), ("yandex", "Yandex"), ("pixabay", "Pixabay"),
]
