"""
DNS paneli view'ları.

Salt-okuma sayfaları (logs) + canlı sunucu kontrolü (servers) asenkron çalışır
ve DNS verisine aiomysql ile erişir (dashboard/db.py). Kimlik doğrulama
Django'nun kendi auth'u (SQLite) ile yapılır; async view'lar ORM'e dokunmadan
oturumu KONTROL eder (SESSION_ENGINE=signed_cookies olduğu için request.session
erişimi async'te güvenlidir).
"""
import asyncio
import ipaddress
import logging
import os
import re
import socket
import threading
import time
from datetime import datetime, timezone

from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.shortcuts import redirect, render
from django.urls import reverse

from project_control.blocklists import normalize_url
from . import db
from .catalog import catalog_grouped
from .services import SERVICES, services_list, CATEGORIES, categories_list, SAFESEARCH_ENGINES
from .upstream_test import test_upstream

# Filtre menüsü + kontrol sayfası için desteklenen yöntemler.
METHODS = ['udp', 'doh', 'dot', 'doq']
METHOD_LABELS = {'udp': 'UDP · düz DNS', 'doh': 'DoH · HTTPS', 'dot': 'DoT · TLS', 'doq': 'DoQ · QUIC'}
METHOD_PORTS = {'udp': 5300, 'doh': 44300, 'dot': 8853, 'doq': 8530}
NEEDS_CERT = {'doh', 'dot', 'doq'}
# Metot -> app_settings anahtarı (panelden ayarlanan iç dinleme portu).
PORT_KEY = {'udp': 'udp_port', 'doh': 'https_port', 'dot': 'dot_port', 'doq': 'doq_port'}

logger = logging.getLogger('dashboard')


def _fail(exc, msg='İşlem sırasında bir hata oluştu.'):
    """Hata AYRINTISINI sunucu günlüğüne (docker logs) yazar, kullanıcıya genel
    mesaj döndürür — exc tipi/metnini panelde göstermek iç yapı bilgisini sızdırır."""
    logger.error('panel hata (%s): %s', type(exc).__name__, exc, exc_info=True)
    return msg


# --------------------------------------------------------------------------- #
# Giriş brute-force koruması: istemci-IP başına başarısız deneme sayacı.
# Panel tek-process uvicorn olduğundan basit in-process yapı yeterli (harici
# bağımlılık yok). Ters proxy (Cloudflare tüneli) arkasında gerçek istemci
# X-Forwarded-For'un ilk değeridir; REMOTE_ADDR tünelin kendisini gösterir.
# --------------------------------------------------------------------------- #
_LOGIN_MAX_FAILS = 5       # bu kadar başarısız denemeden sonra
_LOGIN_LOCK_SECS = 900     # 15 dk kilit
_login_fails: dict = {}    # ip -> (fail_count, window_start_ts)
_login_lock = threading.Lock()


def _client_ip(request):
    """İstemci IP'si — ters proxy arkasında X-Forwarded-For'un ilk değeri."""
    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def _login_locked(ip):
    """IP şu an kilitli mi? (pencere içinde eşik aşıldıysa)"""
    with _login_lock:
        rec = _login_fails.get(ip)
        if not rec:
            return False
        count, start = rec
        if time.time() - start >= _LOGIN_LOCK_SECS:
            _login_fails.pop(ip, None)   # pencere doldu → temizle
            return False
        return count >= _LOGIN_MAX_FAILS


def _login_note_fail(ip):
    """Başarısız denemeyi say; pencere kaymışsa yeniden başlat."""
    with _login_lock:
        rec = _login_fails.get(ip)
        now = time.time()
        if not rec or now - rec[1] >= _LOGIN_LOCK_SECS:
            _login_fails[ip] = (1, now)
        else:
            _login_fails[ip] = (rec[0] + 1, rec[1])


def _login_reset(ip):
    """Başarılı girişte o IP'nin sayacını sıfırla."""
    with _login_lock:
        _login_fails.pop(ip, None)


def _valid_port(s):
    """1–65535 aralığında geçerli bir port değeri mi?"""
    try:
        p = int(str(s).strip())
    except (TypeError, ValueError):
        return False
    return 1 <= p <= 65535


# --------------------------------------------------------------------------- #
# Kimlik doğrulama
# --------------------------------------------------------------------------- #
def setup(request):
    """İlk açılış: hiç kullanıcı yoksa panel sahibini (superuser) oluşturur."""
    if User.objects.exists():
        return redirect('dashboard:login')
    error, username = None, ''
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        if not username or len(password) < 8:
            error = 'Kullanıcı adı gerekli ve parola en az 8 karakter olmalı.'
        else:
            user = User.objects.create_superuser(username=username, password=password)
            auth_login(request, user)
            request.session['panel_username'] = user.username
            return redirect('dashboard:logs')
    return render(request, 'dashboard/login.html', {
        'mode_title': 'Kurulum', 'submit': 'Sahip hesabını oluştur',
        'hint': 'İlk açılış — panel sahibi hesabını oluştur.',
        'pw_autocomplete': 'new-password', 'error': error, 'username': username,
    })


def login_view(request):
    if not User.objects.exists():
        return redirect('dashboard:setup')
    error, username = None, ''
    if request.method == 'POST':
        ip = _client_ip(request)
        if _login_locked(ip):
            logger.warning('giriş kilitli (çok deneme): ip=%s', ip)
            error = 'Çok fazla başarısız deneme. Lütfen bir süre sonra tekrar deneyin.'
        else:
            username = request.POST.get('username', '').strip()
            user = authenticate(request, username=username, password=request.POST.get('password', ''))
            if user is not None:
                _login_reset(ip)
                auth_login(request, user)
                request.session['panel_username'] = user.username
                return redirect(request.GET.get('next') or 'dashboard:logs')
            _login_note_fail(ip)
            logger.warning('başarısız panel girişi: ip=%s', ip)
            error = 'Kullanıcı adı veya parola hatalı.'
    return render(request, 'dashboard/login.html', {
        'mode_title': 'Giriş', 'submit': 'Giriş yap', 'hint': 'Panele erişmek için giriş yap.',
        'pw_autocomplete': 'current-password', 'error': error, 'username': username,
    })


def logout_view(request):
    auth_logout(request)
    return redirect('dashboard:login')


def _gate(request):
    """Async view'lar için ORM'siz oturum kontrolü; yoksa girişe yönlendirir."""
    if not request.session.get('_auth_user_id'):
        return redirect(f"{reverse('dashboard:login')}?next={request.path}")
    return None


def _base_ctx(request, active):
    return {'active': active, 'panel_username': request.session.get('panel_username', '')}


def _sparkline(values, w=280, h=54, pad=6):
    """Değer listesinden mini grafik için SVG polyline noktaları + alan yolu üretir."""
    if not values:
        return None
    mx = max(values) or 1
    n = len(values)
    step = w / (n - 1) if n > 1 else 0
    pts = [(round(i * step, 1), round(h - pad - (v / mx) * (h - 2 * pad), 1)) for i, v in enumerate(values)]
    line = ' '.join(f'{x},{y}' for x, y in pts)
    area = f'M{pts[0][0]},{h} ' + ' '.join(f'L{x},{y}' for x, y in pts) + f' L{pts[-1][0]},{h} Z'
    return {'line': line, 'area': area, 'w': w, 'h': h, 'dx': pts[-1][0], 'dy': pts[-1][1]}


def _sparkline2(totals, blocked, w=680, h=120, pad=12):
    """İki çizgi AYNI ölçekte: toplam (mavi, alan dolgulu) + engellenen (kırmızı)."""
    if not totals:
        return None
    mx = max(totals) or 1
    n = len(totals)
    step = w / (n - 1) if n > 1 else 0

    def _pts(vals):
        return [(round(i * step, 1), round(h - pad - (v / mx) * (h - 2 * pad), 1)) for i, v in enumerate(vals)]

    tp, bp = _pts(totals), _pts(blocked)
    line = ' '.join(f'{x},{y}' for x, y in tp)
    area = f'M{tp[0][0]},{h} ' + ' '.join(f'L{x},{y}' for x, y in tp) + f' L{tp[-1][0]},{h} Z'
    bline = ' '.join(f'{x},{y}' for x, y in bp)
    return {'line': line, 'area': area, 'bline': bline, 'w': w, 'h': h, 'dx': tp[-1][0], 'dy': tp[-1][1]}


def _with_pct(rows, key='cnt'):
    """Her satıra en büyük değere göre yüzde ('pct') ekler — bar genişliği için."""
    mx = max((r[key] for r in rows), default=0) or 1
    return [{**r, 'pct': round(r[key] / mx * 100)} for r in rows]


# --------------------------------------------------------------------------- #
# Sayfalar
# --------------------------------------------------------------------------- #
async def logs(request):
    gate = _gate(request)
    if gate:
        return gate

    context = _base_ctx(request, 'logs')

    try:
        stats, top_domains, top_clients, method_breakdown, hourly = await asyncio.gather(
            db.get_stats(),
            db.get_top_domains(),
            db.get_top_clients(),
            db.get_method_breakdown(),
            db.get_hourly_series(),
        )
    except Exception as exc:  # DB erişilemezse 500 yerine anlaşılır mesaj.
        context['error'] = _fail(exc, 'Veritabanına erişilemedi.')
        return render(request, 'dashboard/logs.html', context)

    context.update(stats=stats, top_domains=top_domains, top_clients=top_clients,
                   method_breakdown=method_breakdown, spark=_sparkline(hourly),
                   peak=max(hourly) if hourly else 0)
    return render(request, 'dashboard/logs.html', context)


QUERIES_CHUNK = 25  # her "+25 daha"da DB'den çekilen satır sayısı


async def queries(request):
    """
    Sorgu geçmişi. İlk yük 25 satır (tam sayfa). "+25 daha" AJAX ile SONRAKİ 25'i
    OFFSET ile çeker (partial=1 → yalnız <tr> parçası döner); önceki satırlar
    tarayıcıda (RAM) kalır, tekrar sorgulanmaz. İstek sınırı JS'te (aynı anda tek
    istek) → hızlı tıklama DB'yi spam'lemez.
    """
    gate = _gate(request)
    if gate:
        return gate

    domain = request.GET.get('q', '').strip()
    method = request.GET.get('method', '').strip()
    try:
        offset = int(request.GET.get('offset', 0))
    except (TypeError, ValueError):
        offset = 0
    offset = max(0, min(offset, 200000))  # üst sınır (aşırı derin sayfalama engeli)
    partial = request.GET.get('partial') == '1'

    try:
        db_rows = await db.get_recent_queries(domain=domain, method=method, limit=QUERIES_CHUNK, offset=offset)
    except Exception as exc:
        if partial:
            return render(request, 'dashboard/_query_rows.html', {'rows': [], 'first': False})
        context = _base_ctx(request, 'queries')
        context.update(q=domain, method=method, methods=METHODS, error=_fail(exc, 'Veritabanına erişilemedi.'))
        return render(request, 'dashboard/queries.html', context)

    if partial:
        # "+25 daha" DB'den devam eder; cache (flush bekleyen) yalnız ilk sayfada üstte.
        return render(request, 'dashboard/_query_rows.html', {'rows': db_rows, 'first': False})

    # İlk sayfa = cache (resolver'ın flush bekleyen tamponu, en üstte) + DB satırları.
    pending = db.read_pending(domain, method)
    rows = pending + db_rows

    context = _base_ctx(request, 'queries')
    context.update(
        q=domain, method=method, methods=METHODS, rows=rows,
        next_offset=offset + len(db_rows), has_more=len(db_rows) == QUERIES_CHUNK,
        pending_count=len(pending),
    )
    return render(request, 'dashboard/queries.html', context)


async def servers(request):
    gate = _gate(request)
    if gate:
        return gate

    context = _base_ctx(request, 'servers')
    msg = None

    if request.method == 'POST':
        method = request.POST.get('method', '')
        if method not in METHODS:
            msg = ('error', 'Geçersiz yöntem.')
        elif 'save_port' in request.POST:
            port = request.POST.get('port', '').strip()
            if not _valid_port(port):
                msg = ('error', 'Geçersiz port (1–65535 arası bir sayı olmalı).')
            else:
                try:
                    await db.set_setting(PORT_KEY[method], port)
                    uygula = ('resolver yeniden başlatılınca' if method == 'udp'
                              else 'metodu kapatıp açınca')
                    msg = ('ok', f'{METHOD_LABELS[method]} iç portu {port} olarak kaydedildi — {uygula} uygulanır.')
                except Exception as exc:
                    msg = ('error', _fail(exc))
        else:
            enabled = request.POST.get('enabled') == '1'
            if method == 'udp' and not enabled:
                msg = ('error', 'UDP kapatılamaz (temel çözümleme).')
            else:
                try:
                    await db.set_method_enabled(method, enabled)
                    durum = 'açıldı' if enabled else 'kapatıldı'
                    msg = ('ok', f'{METHOD_LABELS[method]} {durum} — resolver ~5 sn içinde uygular.')
                except Exception as exc:
                    msg = ('error', _fail(exc))

    try:
        cfg = await db.get_resolver_config()
        app_settings = await db.get_settings()
    except Exception as exc:
        context.update(error=_fail(exc, 'Veritabanına erişilemedi.'), msg=msg)
        return render(request, 'dashboard/servers.html', context)

    context['methods'] = [{
        'key': m, 'label': METHOD_LABELS[m],
        'port': app_settings.get(PORT_KEY[m], str(METHOD_PORTS[m])),
        'enabled': cfg.get(m, False), 'needs_cert': m in NEEDS_CERT,
    } for m in METHODS]
    context['msg'] = msg
    return render(request, 'dashboard/servers.html', context)


# --------------------------------------------------------------------------- #
# Filtreler (blocklist / allowlist) — resolver bu tabloları ~15 sn'de yeniler.
# --------------------------------------------------------------------------- #
_DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$')


def _norm_domain(s: str) -> str:
    return s.strip().rstrip('.').lower()


def _valid_domain(d: str) -> bool:
    return bool(_DOMAIN_RE.match(d))


def _auto_list_name(url: str) -> str:
    """Özel liste URL'sinden kısa bir ad türet (son anlamlı yol parçası, uzantısız;
    yoksa host). İsim verilmeyince tabloda/engellenen sütununda upuzun URL görünmesin."""
    from urllib.parse import urlparse
    p = urlparse(url)
    skip = {'adblock', 'adguard', 'hosts', 'host', 'main', 'master', 'refs', 'heads',
            'raw', 'list', 'lists', 'dns', 'download', 'blocklist'}
    for seg in reversed([s for s in p.path.split('/') if s]):
        base = seg.rsplit('.', 1)[0].strip()
        if base and base.lower() not in skip:
            return base[:48]
    return (p.netloc or 'Özel liste')[:48]


def _norm_rewrite_domain(s: str) -> str:
    """Rewrite anahtarını normalize et; baştaki '*.' wildcard korunur."""
    return s.strip().rstrip('.').lower()


def _valid_rewrite_domain(d: str) -> bool:
    """Tam alan adı ya da '*.sonek' wildcard geçerli mi?"""
    base = d[2:] if d.startswith('*.') else d
    return bool(base) and _valid_domain(base)


def _valid_rewrite_answer(a: str) -> bool:
    """Cevap geçerli bir IP (A/AAAA) ya da hedef alan adı (CNAME) mı?"""
    a = a.strip()
    if not a:
        return False
    try:
        ipaddress.ip_address(a)
        return True
    except ValueError:
        return _valid_domain(a.rstrip('.').lower())


# Zamanlanmış engelleme: gün adları (Python weekday: Pazartesi=0 … Pazar=6).
DAY_NAMES = ['Pzt', 'Sal', 'Çar', 'Per', 'Cum', 'Cmt', 'Paz']


def _hhmm_to_min(s: str):
    """'HH:MM' → gün içi dakika (0–1439); geçersizse None."""
    try:
        h, m = str(s).split(':')
        h, m = int(h), int(m)
    except (ValueError, AttributeError):
        return None
    return h * 60 + m if (0 <= h < 24 and 0 <= m < 60) else None


def _fmt_schedule(r: dict) -> dict:
    """DB satırını panelde gösterime çevir: gün adları + HH:MM aralık."""
    days = [DAY_NAMES[int(x)] for x in str(r['days']).split(',') if x.isdigit() and 0 <= int(x) < 7]
    hhmm = lambda mn: f'{mn // 60:02d}:{mn % 60:02d}'  # noqa: E731
    return {'name': r['name'], 'days': ', '.join(days),
            'start': hhmm(int(r['start_min'])), 'end': hhmm(int(r['end_min']))}


async def filters(request):
    gate = _gate(request)
    if gate:
        return gate

    context = _base_ctx(request, 'filters')
    msg = None

    if request.method == 'POST':
        action = request.POST.get('action', '')
        try:
            # --- Hazır liste (kaynak) işlemleri ---
            if action == 'source_add':
                name = request.POST.get('name', '').strip()
                url = normalize_url(request.POST.get('url', ''))   # GitHub blob linki → ham link
                if not url.startswith(('http://', 'https://')):
                    msg = ('error', 'Geçersiz URL — http:// veya https:// ile başlamalı.')
                else:
                    final_name = name or _auto_list_name(url)   # isim yoksa URL'den kısa ad
                    await db.add_source(final_name, url)
                    msg = ('ok', f'"{final_name}" listesi eklendi — resolver birazdan indirir.')
            elif action == 'source_del':
                await db.remove_source(int(request.POST.get('source_id', 0)))
                msg = ('ok', 'Liste kaldırıldı.')
            elif action == 'source_toggle':
                await db.toggle_source(int(request.POST.get('source_id', 0)),
                                       request.POST.get('enabled') == '1')
                msg = ('ok', 'Liste durumu değişti.')
            elif action == 'source_refresh':
                await db.refresh_source(int(request.POST.get('source_id', 0)))
                msg = ('ok', 'Liste yenileniyor — resolver birazdan yeniden indirir.')
            elif action == 'source_refresh_all':
                await db.refresh_all_sources()
                msg = ('ok', "Tüm listeler yenileniyor — resolver birazdan (2'şerli) yeniden indirir.")
            elif action == 'service_toggle':
                svc = SERVICES.get(request.POST.get('service', ''))
                if svc:
                    en = request.POST.get('enabled') == '1'
                    await db.set_service(svc['name'], svc['domains'], en)
                    msg = ('ok', f"{svc['name']} {'engellendi' if en else 'engeli kaldırıldı'} — resolver ~15 sn içinde uygular.")
            elif action == 'safesearch_engine':
                eng = request.POST.get('engine', '')
                if eng in dict(SAFESEARCH_ENGINES):
                    en = request.POST.get('enabled') == '1'
                    cur = {x for x in (await db.get_settings()).get('safesearch_engines', '').split(',') if x}
                    cur.add(eng) if en else cur.discard(eng)
                    await db.set_setting('safesearch_engines', ','.join(sorted(cur)))
                    msg = ('ok', f"Güvenli arama ({eng}) {'açıldı' if en else 'kapatıldı'} — resolver ~10 sn içinde uygular.")
            elif action == 'category_toggle':
                cat = CATEGORIES.get(request.POST.get('category', ''))
                if cat:
                    if request.POST.get('enabled') == '1':
                        await db.add_source(cat['name'], cat['url'])
                        msg = ('ok', f"{cat['name']} kategorisi engellendi — resolver birazdan indirir.")
                    else:
                        await db.remove_source_by_url(cat['url'])
                        msg = ('ok', f"{cat['name']} kategorisi kaldırıldı.")
            elif action == 'rewrite_add':
                rdomain = _norm_rewrite_domain(request.POST.get('domain', ''))
                answer = request.POST.get('answer', '').strip()
                if not _valid_rewrite_domain(rdomain):
                    msg = ('error', f'Geçersiz alan adı: {rdomain or "(boş)"} (örn. nas.ev ya da *.reklam.com)')
                elif not _valid_rewrite_answer(answer):
                    msg = ('error', f'Geçersiz cevap: {answer or "(boş)"} (IP ya da hedef alan adı olmalı)')
                else:
                    await db.add_rewrite(rdomain, answer)
                    msg = ('ok', f'{rdomain} → {answer} eklendi — resolver ~15 sn içinde uygular.')
            elif action == 'rewrite_manage':
                one = request.POST.get('one', '').strip()
                if one:                                       # tek satır sil
                    await db.remove_rewrite(_norm_rewrite_domain(one))
                    msg = ('ok', 'Kayıt kaldırıldı.')
                else:                                         # seçilenleri sil (toplu)
                    doms = [_norm_rewrite_domain(d) for d in request.POST.getlist('domains') if d.strip()]
                    for d in doms:
                        await db.remove_rewrite(d)
                    msg = ('ok', f'{len(doms)} kayıt kaldırıldı.') if doms else ('error', 'Hiç seçim yapılmadı.')
            elif action == 'schedule_add':
                sname = request.POST.get('service', '').strip()
                valid_names = {v['name'] for v in SERVICES.values()}
                days = [d for d in request.POST.getlist('days') if d in {'0', '1', '2', '3', '4', '5', '6'}]
                smin, emin = _hhmm_to_min(request.POST.get('start', '')), _hhmm_to_min(request.POST.get('end', ''))
                if sname not in valid_names:
                    msg = ('error', 'Geçersiz servis.')
                elif not days:
                    msg = ('error', 'En az bir gün seçmelisin.')
                elif smin is None or emin is None:
                    msg = ('error', 'Geçersiz saat.')
                elif smin == emin:
                    msg = ('error', 'Başlangıç ve bitiş saati aynı olamaz.')
                else:
                    try:
                        tz = int(request.POST.get('tz_offset', '0'))
                    except ValueError:
                        tz = 0
                    await db.set_setting('schedule_tz_offset', str(tz))
                    await db.set_schedule(sname, ','.join(days), smin, emin)
                    msg = ('ok', f'{sname} için zamanlama kaydedildi — resolver ~15 sn içinde uygular.')
            elif action == 'schedule_del':
                await db.remove_schedule(request.POST.get('name', '').strip())
                msg = ('ok', 'Zamanlama kaldırıldı.')
            else:
                # --- Elle domain işlemleri ---
                domain = _norm_domain(request.POST.get('domain', ''))
                if action in ('block_add', 'allow_add') and not _valid_domain(domain):
                    msg = ('error', f'Geçersiz alan adı: {domain or "(boş)"}')
                elif action == 'block_add':
                    await db.add_block(domain)
                    msg = ('ok', f'{domain} engellendi.')
                elif action == 'block_del':
                    await db.remove_block(domain)
                    msg = ('ok', f'{domain} engel listesinden çıkarıldı.')
                elif action == 'allow_add':
                    await db.add_allow(domain)
                    msg = ('ok', f'{domain} izin listesine eklendi.')
                elif action == 'allow_del':
                    await db.remove_allow(domain)
                    msg = ('ok', f'{domain} izin listesinden çıkarıldı.')
                elif action in ('block_manage', 'allow_manage'):
                    remove = db.remove_block if action == 'block_manage' else db.remove_allow
                    one = request.POST.get('one', '').strip()
                    if one:                                   # tek satır sil
                        await remove(_norm_domain(one))
                        msg = ('ok', 'Kaldırıldı.')
                    else:                                     # seçilenleri sil (toplu)
                        doms = [_norm_domain(d) for d in request.POST.getlist('domains') if d.strip()]
                        for d in doms:
                            await remove(d)
                        msg = ('ok', f'{len(doms)} kayıt kaldırıldı.') if doms else ('error', 'Hiç seçim yapılmadı.')
        except Exception as exc:
            msg = ('error', _fail(exc))

    try:
        blocklist, allowlist, sources, enabled_services, app_set, rewrites, schedules = await asyncio.gather(
            db.get_blocklist(), db.get_allowlist(), db.get_sources(),
            db.get_enabled_services(), db.get_settings(), db.get_rewrites(), db.get_schedules())
    except Exception as exc:
        context.update(error=_fail(exc, 'Veritabanına erişilemedi.'), msg=msg)
        return render(request, 'dashboard/filters.html', context)

    added_urls = [s['url'] for s in sources]
    context.update(
        blocklist=blocklist, allowlist=allowlist, sources=sources,
        catalog=catalog_grouped(), added_urls=added_urls, msg=msg,
        rewrites=rewrites, rewrite_count=len(rewrites),
        schedules=[_fmt_schedule(r) for r in schedules],
        block_count=len(blocklist), allow_count=len(allowlist),
        source_count=len(sources), total_list_domains=sum(s['count'] for s in sources),
        services=[{'id': sid, 'name': name, 'enabled': name in enabled_services}
                  for sid, name in services_list()],
        safesearch_engines=[{'id': eid, 'name': name,
                             'enabled': eid in {x for x in app_set.get('safesearch_engines', '').split(',') if x}}
                            for eid, name in SAFESEARCH_ENGINES],
        categories=[{'id': cid, 'name': name, 'enabled': url in added_urls}
                    for cid, name, url in categories_list()],
    )
    return render(request, 'dashboard/filters.html', context)


async def analytics(request):
    """Analiz — zaman serisi + method/kayıt-tipi dağılımı + top domain/istemci."""
    gate = _gate(request)
    if gate:
        return gate

    context = _base_ctx(request, 'analytics')
    try:
        stats, hourly, methods, rtypes, tdomains, tclients, blocks, bdomains = await asyncio.gather(
            db.get_stats(),
            db.get_hourly_detail(),
            db.get_method_breakdown(),
            db.get_record_type_breakdown(),
            db.get_top_domains(20),
            db.get_top_clients(10),
            db.get_block_breakdown(),
            db.get_top_blocked_domains(20),
        )
    except Exception as exc:
        context['error'] = _fail(exc, 'Veritabanına erişilemedi.')
        return render(request, 'dashboard/analytics.html', context)

    totals = [h['total'] for h in hourly]
    blocked = [h['blocked'] for h in hourly]
    context.update(
        stats=stats, spark=_sparkline2(totals, blocked, w=680, h=120, pad=12),
        peak=max(totals) if totals else 0, hourly=hourly,
        methods=_with_pct(methods), rtypes=_with_pct(rtypes),
        tdomains=_with_pct(tdomains), tclients=_with_pct(tclients),
        blocks=_with_pct(blocks), block_total=stats.get('blocked', 0),
        blocked_domains=_with_pct(bdomains),
        source_times=_source_times(),
    )
    return render(request, 'dashboard/analytics.html', context)


def _source_times():
    """Kaynak bazında ortalama işlem süreleri (çekirdek + önbellek + upstream'ler)."""
    rows = [{'name': k, 'avg': v.get('avg_ms'), 'count': v.get('count', 0)}
            for k, v in db.read_source_stats().items() if v.get('avg_ms') is not None]
    rows.sort(key=lambda r: r['avg'])
    mx = max((r['avg'] for r in rows), default=0) or 1
    for r in rows:
        r['pct'] = round(r['avg'] / mx * 100)
    return rows


def users(request):
    """Panel kullanıcıları (Django auth). Sync view — ORM kullanır, oturumu session'dan kontrol eder."""
    if not request.session.get('_auth_user_id'):
        return redirect(f"{reverse('dashboard:login')}?next={request.path}")

    msg = None
    if request.method == 'POST':
        action = request.POST.get('action', '')
        if action == 'add':
            username = request.POST.get('username', '').strip()
            password = request.POST.get('password', '')
            is_admin = request.POST.get('is_admin') == '1'
            if not username or len(password) < 8:
                msg = ('error', 'Kullanıcı adı gerekli ve parola en az 8 karakter olmalı.')
            elif User.objects.filter(username=username).exists():
                msg = ('error', f'"{username}" zaten var.')
            else:
                User.objects.create_user(username=username, password=password,
                                         is_staff=is_admin, is_superuser=is_admin)
                msg = ('ok', f'"{username}" eklendi.')
        elif action == 'del':
            uid = request.POST.get('user_id', '')
            if str(request.session.get('_auth_user_id')) == str(uid):
                msg = ('error', 'Kendi hesabını silemezsin.')
            else:
                target = User.objects.filter(id=uid).first()
                if target and target.is_superuser and User.objects.filter(is_superuser=True).count() <= 1:
                    msg = ('error', 'Son yöneticiyi silemezsin.')
                else:
                    User.objects.filter(id=uid).delete()
                    msg = ('ok', 'Kullanıcı silindi.')

    ulist = list(User.objects.order_by('-is_superuser', 'username')
                 .values('id', 'username', 'is_superuser', 'last_login', 'date_joined'))
    context = _base_ctx(request, 'users')
    context.update(users=ulist, msg=msg, me=str(request.session.get('_auth_user_id')))
    return render(request, 'dashboard/users.html', context)


# --------------------------------------------------------------------------- #
# Sertifika (DoT/DoH/DoQ) — yol panelden ayarlanır + doğrulama gösterilir
# --------------------------------------------------------------------------- #
def _cert_path(p):
    """Göreli cert yolunu /app köküne göre çöz (panel cwd'si /app/dns_resolver)."""
    if not p:
        return ''
    return p if os.path.isabs(p) else os.path.join('/app', p)


def check_cert(path):
    """Sertifikayı oku + doğrula (cryptography). subject/issuer/valid_until/status/days döner."""
    real = _cert_path(path)
    if not real:
        return {'error': 'Yol boş'}
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        with open(real, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        return {'error': f'Dosya bulunamadı: {real}'}
    except Exception as exc:
        return {'error': _fail(exc, 'Sertifika okunamadı (geçersiz dosya?).')}
    try:
        na = cert.not_valid_after_utc
    except AttributeError:
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
    days = (na - datetime.now(timezone.utc)).days

    def _cn(name):
        try:
            return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            return name.rfc4514_string()

    status = 'EXPIRED' if days < 0 else ('EXPIRING' if days < 30 else 'VALID')
    return {'subject': _cn(cert.subject), 'issuer': _cn(cert.issuer),
            'valid_until': na.strftime('%Y-%m-%d %H:%M UTC'),
            'valid_until_iso': na.strftime('%Y-%m-%d %H:%M:%S'), 'days': days, 'status': status}


async def certificate(request):
    gate = _gate(request)
    if gate:
        return gate

    context = _base_ctx(request, 'certificate')
    msg = None
    if request.method == 'POST':
        cert_file = request.POST.get('cert_file', '').strip()
        key_file = request.POST.get('key_file', '').strip()
        try:
            if cert_file:
                await db.set_setting('cert_file', cert_file)
            if key_file:
                await db.set_setting('key_file', key_file)
            msg = ('ok', "Sertifika yolları kaydedildi — Sunucular'dan DoT/DoH/DoQ'yu kapatıp açınca yeni sertifika yüklenir.")
        except Exception as exc:
            msg = ('error', _fail(exc))

    try:
        settings = await db.get_settings()
    except Exception as exc:
        context.update(error=_fail(exc, 'Veritabanına erişilemedi.'), msg=msg)
        return render(request, 'dashboard/certificate.html', context)

    cert_file = settings.get('cert_file', '')
    key_file = settings.get('key_file', '')
    context.update(
        msg=msg, cert_file=cert_file, key_file=key_file,
        cert=check_cert(cert_file),
        key_exists=bool(key_file) and os.path.exists(_cert_path(key_file)),
    )
    return render(request, 'dashboard/certificate.html', context)


# --------------------------------------------------------------------------- #
# Kurulum / Domain rehberi — bağlantı adresleri (nerede çalışıyorsa ona göre)
# --------------------------------------------------------------------------- #
def _server_ips():
    """Sunucunun loopback olmayan IPv4 adresleri (dns-net'te tipik: 172.27.17.2)."""
    ips, seen = [], set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))            # paket gönderilmez, sadece rota seçilir
        ip = s.getsockname()[0]
        s.close()
        if not ip.startswith('127.'):
            seen.add(ip); ips.append(ip)
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in seen and not ip.startswith('127.'):
                seen.add(ip); ips.append(ip)
    except Exception:
        pass
    return ips


def _connection_endpoints(cfg, ports, domain, addrs):
    """Açık yöntemlere göre bağlantı uç noktaları. Domain = STANDART port (host dış
    yayını 443/853'ü iç porta eşler → domainde port yazılmaz); dns-net IP = konteynerin
    İÇ portu (doğrudan erişim)."""
    conn = []
    if cfg.get('udp'):
        items = []
        if domain:
            items.append(domain)                                    # standart 53
        items += [a + ':' + ports['udp'] for a in addrs]            # dns-net: iç port
        conn.append({'m': 'UDP', 'label': 'Düz DNS (UDP/TCP)', 'cert': False,
                     'items': items or ['<sunucu-ip>:' + ports['udp']]})
    enc = [
        ('doh', 'DoH', 'DNS-over-HTTPS', 'https://', '/dns-query'),
        ('dot', 'DoT', 'DNS-over-TLS', 'tls://', ''),
        ('doq', 'DoQ', 'DNS-over-QUIC', 'quic://', ''),
    ]
    for key, m, label, scheme, path in enc:
        if not cfg.get(key):
            continue
        p = ports[key]
        items = []
        if domain:
            items.append(scheme + domain + path)                    # standart 443/853
        items += [scheme + a + ':' + p + path for a in addrs]       # dns-net: iç port
        conn.append({'m': m, 'label': label, 'cert': True,
                     'items': items or [scheme + '<sunucu-ip>:' + p + path]})
    return conn


async def guide(request):
    gate = _gate(request)
    if gate:
        return gate

    context = _base_ctx(request, 'guide')
    # Canlı iç portlar (Sunucular'dan ayarlanır); DB yoksa varsayılan.
    ports = {m: str(p) for m, p in METHOD_PORTS.items()}
    cfg = {'udp': True, 'doh': False, 'dot': False, 'doq': False}
    try:
        app_settings = await db.get_settings()
        for m, key in PORT_KEY.items():
            if app_settings.get(key):
                ports[m] = app_settings[key]
    except Exception:
        pass
    try:
        cfg = await db.get_resolver_config()
    except Exception:
        pass

    # "Nerede çalışıyorsa ona göre": panele eriştiğin host + sunucunun IP'leri.
    try:
        req_host = request.get_host()
    except Exception:
        req_host = ''
    req_addr = req_host.split(':')[0]
    ips = _server_ips()
    addrs = list(ips)
    if req_addr and req_addr not in addrs and req_addr != 'localhost' and not req_addr.startswith('127.'):
        addrs.insert(0, req_addr)          # domain/LAN ile eriştiysen onu öne al

    domain = os.getenv('ALLOWED_HOST', '').strip()
    if domain in ('localhost', '127.0.0.1'):
        domain = ''

    context.update(
        ports=ports,
        conn=_connection_endpoints(cfg, ports, domain, addrs),
        req_host=req_host, server_ips=ips, domain=domain,
        subnet='172.27.17.0/24', host_ip='172.27.17.1', container_ip='172.27.17.2',
        install_dir='/opt/DNS_RESOLVER', db_name='dns_db', db_user='dns_user',
    )
    return render(request, 'dashboard/guide.html', context)


# --------------------------------------------------------------------------- #
# Genel Ayarlar — geçmiş aç/kapa + önbellek (resolver ~10 sn'de uygular)
# --------------------------------------------------------------------------- #
async def settings_page(request):
    gate = _gate(request)
    if gate:
        return gate

    context = _base_ctx(request, 'settings')
    msg = None
    test_results = None
    if request.method == 'POST':
        try:
            if 'clear_cache' in request.POST:
                stamp = str(int(datetime.now(timezone.utc).timestamp()))
                await db.set_setting('cache_clear_at', stamp)
                msg = ('ok', 'Önbellek temizleme istendi — resolver ~10 sn içinde uygular.')
            elif 'clear_history' in request.POST:
                await db.clear_history()
                msg = ('ok', 'Sorgu geçmişi (veritabanı) temizlendi.')
            elif 'test_upstreams' in request.POST:
                _ups = [ln.strip() for ln in request.POST.get('upstreams', '').replace(',', '\n').splitlines() if ln.strip()]
                if _ups:
                    test_results = list(await asyncio.gather(*[asyncio.to_thread(test_upstream, u) for u in _ups]))
                    msg = ('ok', f'{len(_ups)} sunucu test edildi.')
                else:
                    msg = ('error', 'Test edilecek upstream yok — önce ekle.')
            else:
                mn = request.POST.get('cache_min_ttl', '0').strip()
                mx = request.POST.get('cache_max_ttl', '86400').strip()
                if not (mn.isdigit() and mx.isdigit() and int(mx) >= 1 and int(mn) <= int(mx)):
                    msg = ('error', 'TTL değerleri geçersiz (0 ≤ min ≤ max, max ≥ 1).')
                else:
                    await db.set_setting('log_queries', '1' if request.POST.get('log_queries') else '0')
                    await db.set_setting('cache_enabled', '1' if request.POST.get('cache_enabled') else '0')
                    await db.set_setting('cache_min_ttl', str(int(mn)))
                    await db.set_setting('cache_max_ttl', str(int(mx)))
                    await db.set_setting('use_recursion', '1' if request.POST.get('use_recursion') else '0')
                    await db.set_setting('upstreams', request.POST.get('upstreams', '').strip())
                    _strat = request.POST.get('upstream_strategy', 'sequential')
                    await db.set_setting('upstream_strategy',
                                         _strat if _strat in ('sequential', 'parallel', 'fastest') else 'sequential')
                    await db.set_setting('conditional_forwards', request.POST.get('conditional_forwards', '').strip())
                    # Erişim kontrolü
                    _rl = request.POST.get('rate_limit', '0').strip()
                    await db.set_setting('rate_limit', _rl if _rl.isdigit() else '0')
                    await db.set_setting('client_allow', request.POST.get('client_allow', '').strip())
                    await db.set_setting('client_deny', request.POST.get('client_deny', '').strip())
                    # Log retention (preset ya da özel)
                    _rd = request.POST.get('log_retention_days', '0')
                    if _rd == 'custom':
                        _rc = request.POST.get('log_retention_custom', '0').strip()
                        _rd = _rc if (_rc.isdigit() and int(_rc) > 0) else '0'
                    await db.set_setting('log_retention_days', _rd if _rd.isdigit() else '0')
                    msg = ('ok', 'Ayarlar kaydedildi — resolver ~10 sn içinde uygular.')
        except Exception as exc:
            msg = ('error', _fail(exc))

    try:
        s = await db.get_settings()
    except Exception as exc:
        context.update(error=_fail(exc, 'Veritabanına erişilemedi.'), msg=msg)
        return render(request, 'dashboard/settings.html', context)

    context.update(
        msg=msg,
        log_queries=s.get('log_queries', '1') != '0',
        cache_enabled=s.get('cache_enabled', '1') != '0',
        cache_min_ttl=s.get('cache_min_ttl', '0'),
        cache_max_ttl=s.get('cache_max_ttl', '86400'),
        use_recursion=s.get('use_recursion', '1') != '0',
        upstreams=s.get('upstreams', ''),
        upstream_strategy=s.get('upstream_strategy', 'sequential'),
        conditional_forwards=s.get('conditional_forwards', ''),
        upstream_rows=_upstream_rows(s.get('upstreams', '')),
        rate_limit=s.get('rate_limit', '0'),
        client_allow=s.get('client_allow', ''),
        client_deny=s.get('client_deny', ''),
        retention_presets=['0', '7', '14', '30', '90', '365'],
        retention_days=s.get('log_retention_days', '0'),
        retention_is_custom=s.get('log_retention_days', '0') not in {'0', '7', '14', '30', '90', '365'},
        upstream_test=test_results,
    )
    return render(request, 'dashboard/settings.html', context)


def _upstream_rows(upstreams_raw):
    """Yapılandırılan upstream'leri ölçülen ortalama tepki süreleriyle eşle."""
    ups = [ln.strip() for ln in upstreams_raw.replace(',', '\n').splitlines() if ln.strip()]
    stats = db.read_source_stats()
    return [{'up': u, 'avg': stats.get(u, {}).get('avg_ms'),
             'count': stats.get(u, {}).get('count', 0)} for u in ups]
