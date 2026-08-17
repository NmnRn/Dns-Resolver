"""User-Agent stringinden okunur tarayıcı/OS/cihaz çıkarımı (bağımlılıksız).

Tam bir cihaz fingerprint'i DEĞİLDİR — HTTP yalnız User-Agent verir; bu da
istemcinin bildirdiği (ve taklit edilebilen) bir metindir. Panel 'Cihazlar'
sayfasında kaba/okunur bir tanı göstermek içindir.
"""


def parse_user_agent(ua: str) -> dict:
    """UA metninden {'browser','os','device'} döndürür (bilinmiyorsa 'Bilinmeyen')."""
    low = (ua or '').lower()

    # --- İşletim sistemi ---
    if 'windows nt 10' in low or 'windows nt 11' in low:
        os_name = 'Windows 10/11'
    elif 'windows' in low:
        os_name = 'Windows'
    elif 'iphone' in low or 'ipad' in low:
        os_name = 'iOS'
    elif 'android' in low:
        os_name = 'Android'
    elif 'mac os x' in low or 'macintosh' in low:
        os_name = 'macOS'
    elif 'cros' in low:
        os_name = 'ChromeOS'
    elif 'linux' in low:
        os_name = 'Linux'
    else:
        os_name = 'Bilinmeyen'

    # --- Tarayıcı (SIRA önemli: Edge/Opera Chrome'dan, Chrome Safari'den önce) ---
    if 'edg/' in low or 'edga/' in low or 'edgios/' in low:
        browser = 'Edge'
    elif 'opr/' in low or ' opera' in low:
        browser = 'Opera'
    elif 'samsungbrowser' in low:
        browser = 'Samsung Internet'
    elif 'firefox/' in low or 'fxios/' in low:
        browser = 'Firefox'
    elif 'chrome/' in low or 'crios/' in low:
        browser = 'Chrome'
    elif 'safari' in low:
        browser = 'Safari'
    elif 'curl/' in low:
        browser = 'curl'
    elif 'wget' in low:
        browser = 'wget'
    else:
        browser = 'Bilinmeyen'

    # --- Cihaz türü ---
    if 'ipad' in low or 'tablet' in low:
        device = 'Tablet'
    elif 'mobile' in low or 'iphone' in low or 'android' in low:
        device = 'Mobil'
    else:
        device = 'Masaüstü'

    return {'browser': browser, 'os': os_name, 'device': device}
