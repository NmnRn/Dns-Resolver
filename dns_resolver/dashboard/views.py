"""
DNS paneli view'ları.

Salt-okuma sayfaları (logs) + canlı sunucu kontrolü (servers) asenkron çalışır
ve DNS verisine aiomysql ile erişir (dashboard/db.py). Kimlik doğrulama
Django'nun kendi auth'u (SQLite) ile yapılır; async view'lar ORM'e dokunmadan
oturumu KONTROL eder (SESSION_ENGINE=signed_cookies olduğu için request.session
erişimi async'te güvenlidir).
"""
import asyncio
import csv
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
import uuid
from datetime import datetime, timezone

from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.db.models import F
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext as _

import logcrypto  # DeviceProfile PII alanlarını at-rest şifreler/çözer (DNS_LOG_KEY)
import config_store  # sunucu topolojisi (aç/kapa + portlar) TEK kaynak: config/servers.json
from project_control.blocklists import normalize_url, check_link
from . import db
from .catalog import catalog_grouped
from .models import PanelLogin, DeviceProfile
from .useragent import parse_user_agent
from .services import SERVICES, services_list, CATEGORIES, categories_list, SAFESEARCH_ENGINES
from .upstream_test import test_upstream

# Filtre menüsü + kontrol sayfası için desteklenen yöntemler.
METHODS = ['udp', 'doh', 'dot', 'doq']
METHOD_LABELS = {'udp': 'UDP · düz DNS', 'doh': 'DoH · HTTPS', 'dot': 'DoT · TLS', 'doq': 'DoQ · QUIC'}
METHOD_PORTS = {'udp': 5300, 'doh': 44300, 'dot': 8853, 'doq': 8530}
NEEDS_CERT = {'doh', 'dot', 'doq'}
# NOT: port/aç-kapa artık config_store (config/servers.json); DB/env değil.

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


_PANEL_LOGIN_KEEP = 1000   # denetim tablosunu makul tut (en yeni N kayıt)


def _record_panel_login(request, username):
    """Başarılı panel girişini denetim tablosuna yaz (IP + User-Agent + zaman).
    Girişi ASLA bloklamasın diye hata yutulur; tablo en yeni N kayıtla sınırlanır."""
    try:
        PanelLogin.objects.create(
            username=username,
            ip=_client_ip(request),
            user_agent=(request.META.get('HTTP_USER_AGENT', '') or '')[:1000],
        )
        extra = PanelLogin.objects.count() - _PANEL_LOGIN_KEEP
        if extra > 0:
            old = list(PanelLogin.objects.order_by('created_at')
                       .values_list('id', flat=True)[:extra])
            PanelLogin.objects.filter(id__in=old).delete()
    except Exception:   # noqa: BLE001 — denetim kaydı girişi bozmasın
        logger.exception('panel giris denetim kaydi yazilamadi')


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
            error = _('Kullanıcı adı gerekli ve parola en az 8 karakter olmalı.')
        else:
            user = User.objects.create_superuser(username=username, password=password)
            auth_login(request, user)
            request.session['panel_username'] = user.username
            request.session['is_admin'] = True
            _record_panel_login(request, user.username)
            return redirect('dashboard:logs')
    return render(request, 'dashboard/login.html', {
        'mode_title': _('Kurulum'), 'submit': _('Sahip hesabını oluştur'),
        'hint': _('İlk açılış — panel sahibi hesabını oluştur.'),
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
            error = _('Çok fazla başarısız deneme. Lütfen bir süre sonra tekrar deneyin.')
        else:
            username = request.POST.get('username', '').strip()
            user = authenticate(request, username=username, password=request.POST.get('password', ''))
            if user is not None and not user.is_superuser:
                # Panel YALNIZ yoneticilere: parola dogru ama yetkisiz → kilit sayaci ARTMAZ.
                logger.warning('yonetici olmayan giris denemesi: kullanici=%s ip=%s', username, ip)
                error = _('Bu panele yalnızca yöneticiler erişebilir.')
            elif user is not None:
                _login_reset(ip)
                auth_login(request, user)
                request.session['panel_username'] = user.username
                request.session['is_admin'] = True
                _record_panel_login(request, user.username)
                # Açık yönlendirme koruması: next YALNIZCA aynı-host/relatif ise izinli.
                nxt = request.GET.get('next') or ''
                if nxt and url_has_allowed_host_and_scheme(
                        nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
                    return redirect(nxt)
                return redirect('dashboard:logs')
            else:
                _login_note_fail(ip)
                logger.warning('başarısız panel girişi: ip=%s', ip)
                error = _('Kullanıcı adı veya parola hatalı.')
    return render(request, 'dashboard/login.html', {
        'mode_title': _('Giriş'), 'submit': _('Giriş yap'), 'hint': _('Panele erişmek için giriş yap.'),
        'pw_autocomplete': 'current-password', 'error': error, 'username': username,
    })


def logout_view(request):
    auth_logout(request)
    return redirect('dashboard:login')


def _gate(request):
    """Panel YALNIZ yöneticilere. Async view'lar için ORM'siz oturum kontrolü:
    giriş yoksa login'e; giriş var ama yönetici değilse (is_admin bayrağı) çıkışa
    yönlendirir (yetkisiz/eski oturumu temizler)."""
    if not request.session.get('_auth_user_id'):
        return redirect(f"{reverse('dashboard:login')}?next={request.path}")
    if not request.session.get('is_admin'):
        return redirect('dashboard:logout')
    return None


def _base_ctx(request, active):
    return {'active': active, 'panel_username': request.session.get('panel_username', ''),
            'is_admin': request.session.get('is_admin', False)}


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

    m_total = sum(m['cnt'] for m in method_breakdown) or 1
    total = stats.get('total', 0) or 1
    context.update(
        stats=stats,
        top_domains=_with_pct(top_domains),
        top_clients=_with_pct(top_clients),
        methods=[{**m, 'share': round(m['cnt'] / m_total * 100, 1)} for m in method_breakdown],
        blocked_pct=round(stats.get('blocked', 0) / total * 100),
        spark=_sparkline(hourly),
        peak=max(hourly) if hourly else 0,
    )
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
    client_ip = request.GET.get('ip', '').strip()
    dnssec = request.GET.get('dnssec', '').strip()
    try:
        offset = int(request.GET.get('offset', 0))
    except (TypeError, ValueError):
        offset = 0
    offset = max(0, min(offset, 200000))  # üst sınır (aşırı derin sayfalama engeli)
    partial = request.GET.get('partial') == '1'

    try:
        db_rows = await db.get_recent_queries(domain=domain, method=method, client_ip=client_ip, dnssec=dnssec, limit=QUERIES_CHUNK, offset=offset)
    except Exception as exc:
        if partial:
            return render(request, 'dashboard/_query_rows.html', {'rows': [], 'first': False})
        context = _base_ctx(request, 'queries')
        context.update(q=domain, method=method, ip=client_ip, dnssec=dnssec, methods=METHODS, error=_fail(exc, 'Veritabanına erişilemedi.'))
        return render(request, 'dashboard/queries.html', context)

    if partial:
        # "+25 daha" DB'den devam eder; cache (flush bekleyen) yalnız ilk sayfada üstte.
        return render(request, 'dashboard/_query_rows.html', {'rows': db_rows, 'first': False})

    # İlk sayfa = cache (resolver'ın flush bekleyen tamponu, en üstte) + DB satırları.
    pending = db.read_pending(domain, method, client_ip, dnssec)
    rows = pending + db_rows

    context = _base_ctx(request, 'queries')
    context.update(
        q=domain, method=method, ip=client_ip, dnssec=dnssec, methods=METHODS, rows=rows,
        next_offset=offset + len(db_rows), has_more=len(db_rows) == QUERIES_CHUNK,
        pending_count=len(pending),
    )
    return render(request, 'dashboard/queries.html', context)


async def queries_export(request):
    """Sorgu geçmişini CSV olarak indir (aynı q/method filtresiyle; client_ip+domain çözülü)."""
    gate = _gate(request)
    if gate:
        return gate
    domain = request.GET.get('q', '').strip()
    method = request.GET.get('method', '').strip()
    client_ip = request.GET.get('ip', '').strip()
    dnssec = request.GET.get('dnssec', '').strip()
    try:
        rows = await db.get_queries_for_export(domain=domain, method=method, client_ip=client_ip, dnssec=dnssec)
    except Exception as exc:
        _fail(exc)
        return redirect('dashboard:queries')
    buf = io.StringIO()
    buf.write('\ufeff')                     # UTF-8 BOM → Excel Türkçe karakterleri doğru okusun
    w = csv.writer(buf)
    w.writerow(['tarih (UTC)', 'domain', 'tip', 'istemci', 'yontem', 'engellendi', 'engelleyen', 'kaynak', 'dnssec'])
    for r in rows:
        w.writerow([r['queried_at'], r['domain'], r['record_type'], r['client_ip'], r['method'],
                    'evet' if r['blocked'] else 'hayir', r.get('blocked_by') or '', r.get('resolved_by') or '',
                    r.get('dnssec') or ''])
    fname = f"dns-gecmis-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    resp = HttpResponse(buf.getvalue(), content_type='text/csv; charset=utf-8')
    resp['Content-Disposition'] = f'attachment; filename="{fname}"'
    return resp


async def servers(request):
    gate = _gate(request)
    if gate:
        return gate

    context = _base_ctx(request, 'servers')
    msg = None

    if request.method == 'POST':
        method = request.POST.get('method', '')
        action = request.POST.get('action', 'toggle')
        if method not in METHODS:
            msg = ('error', 'Geçersiz yöntem.')
        else:
            cfg = config_store.get_config()
            m = cfg['methods'][method]
            if action == 'toggle':
                enabled = request.POST.get('enabled') == '1'
                if method == 'udp' and not enabled:
                    msg = ('error', 'UDP kapatılamaz (temel çözümleme).')
                else:
                    m['enabled'] = enabled
                    config_store.write_config(cfg)
                    durum = 'açıldı' if enabled else 'kapatıldı'
                    msg = ('ok', f'{METHOD_LABELS[method]} {durum} — resolver ~5 sn içinde uygular.')
            elif action == 'ports':
                def _port(name, cur):
                    try:
                        p = int(request.POST.get(name, cur))
                        return p if 1 <= p <= 65535 else cur
                    except (TypeError, ValueError):
                        return cur
                new_cp = _port('container_port', m['container_port'])
                new_ep = _port('external_port', m['external_port'])
                new_pub = request.POST.get('publish') == '1'
                host_changed = (new_ep != m['external_port']) or (new_pub != m['publish'])
                m['container_port'], m['external_port'], m['publish'] = new_cp, new_ep, new_pub
                config_store.write_config(cfg)
                if host_changed:
                    msg = ('ok', f'{METHOD_LABELS[method]} portları kaydedildi — host yayınının '
                                 'etki etmesi için sunucuda ./start.sh çalıştır.')
                else:
                    msg = ('ok', f'{METHOD_LABELS[method]} iç portu kaydedildi — resolver ~5 sn içinde uygular.')

    cfg = config_store.get_config()
    context['methods'] = [{
        'key': m, 'label': METHOD_LABELS[m],
        'container_port': cfg['methods'][m]['container_port'],
        'external_port': cfg['methods'][m]['external_port'],
        'publish': cfg['methods'][m]['publish'],
        'enabled': cfg['methods'][m]['enabled'], 'needs_cert': m in NEEDS_CERT,
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


_LABEL_RE = re.compile(r'^[a-z0-9](-?[a-z0-9])*$')


def _valid_block_domain(d: str) -> bool:
    """Engelleme/izin girişi: tam alan adı YA DA '*.sonek' wildcard.
    Örn: *.example.com (alt alanlar), *.onion / *.local (tek-etiket sonek de olur)."""
    if d.startswith('*.'):
        base = d[2:]
        return bool(base) and all(_LABEL_RE.match(lbl) for lbl in base.split('.'))
    return _valid_domain(d)


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
                if action in ('block_add', 'allow_add') and not _valid_block_domain(domain):
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
        stats, hourly, methods, rtypes, tdomains, tclients, blocks, bdomains, dnssec = await asyncio.gather(
            db.get_stats(),
            db.get_hourly_detail(),
            db.get_method_breakdown(),
            db.get_record_type_breakdown(),
            db.get_top_domains(20),
            db.get_top_clients(10),
            db.get_block_breakdown(),
            db.get_top_blocked_domains(20),
            db.get_dnssec_breakdown(),
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
        dnssec=dnssec,
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
    uid = request.session.get('_auth_user_id')
    if not uid:
        return redirect(f"{reverse('dashboard:login')}?next={request.path}")
    # YETKİ: kullanıcı yönetimi YALNIZCA yöneticiye (is_superuser). ORM ile doğrula
    # (session bayrağına güvenme) — aksi halde normal kullanıcı admin hesabı açabilir.
    if not User.objects.filter(id=uid, is_superuser=True).exists():
        return redirect('dashboard:logs')

    msg = None
    if request.method == 'POST':
        action = request.POST.get('action', '')
        if action == 'add':
            username = request.POST.get('username', '').strip()
            password = request.POST.get('password', '')
            if not username or len(password) < 8:
                msg = ('error', 'Kullanıcı adı gerekli ve parola en az 8 karakter olmalı.')
            elif User.objects.filter(username=username).exists():
                msg = ('error', f'"{username}" zaten var.')
            else:
                # Tek rol: tüm panel kullanıcıları yönetici (is_superuser).
                User.objects.create_user(username=username, password=password,
                                         is_staff=True, is_superuser=True)
                msg = ('ok', f'"{username}" eklendi (yönetici).')
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


def devices(request):
    """Cihazlar: panele erişen benzersiz cihazlar — her sayfa açılışında fingerprint
    toplanıp DEDUP'lanır; her cihaz TIKLANINCA tam özelliklerini (ekran/GPU/canvas...)
    açar. Son görülene göre = 'son giriş yapılan yerler'. Yalnız yöneticiye.
    (Eski 'Cihaz Özellikleri' sayfası buraya taşındı.)"""
    uid = request.session.get('_auth_user_id')
    if not uid:
        return redirect(f"{reverse('dashboard:login')}?next={request.path}")
    if not User.objects.filter(id=uid, is_superuser=True).exists():
        return redirect('dashboard:logs')

    msg = None
    if request.method == 'POST':
        act = request.POST.get('action', '')
        if act == 'clear_devices':
            n = DeviceProfile.objects.all().delete()[0]
            request.session.pop('fp_last', None)     # sonraki açılışta yeniden kaydedilsin
            msg = ('ok', _('%(n)s cihaz kaydı silindi.') % {'n': n})
        elif act == 'del_device':
            DeviceProfile.objects.filter(id=request.POST.get('id', '')).delete()
            msg = ('ok', _('Cihaz silindi.'))

    devs = list(DeviceProfile.objects.order_by('-last_seen')[:200].values(
        'id', 'ip', 'ips', 'volatile', 'browser', 'os', 'device', 'screen', 'viewport',
        'timezone', 'platform', 'languages', 'color_depth', 'cpu', 'memory', 'gpu', 'touch',
        'canvas_hash', 'brave', 'fp_protected', 'username', 'first_seen', 'last_seen',
        'hits', 'user_agent'))
    # PII alanlarını gösterim için ÇÖZ (at-rest şifreli; anahtar yoksa zaten düz)
    _DEC = ('ip', 'ips', 'user_agent', 'screen', 'viewport', 'timezone',
            'platform', 'languages', 'gpu', 'canvas_hash')
    for d in devs:
        for k in _DEC:
            d[k] = logcrypto.dec(d.get(k) or '')
        # Görülen IP'ler → tıklanabilir rozet listesi (WHOIS için)
        d['ips_list'] = [ip for ip in (d['ips'] or d['ip'] or '').split(',') if ip]
    context = _base_ctx(request, 'devices')
    context.update(
        devices=devs, msg=msg,
        total=DeviceProfile.objects.count(),
        # Benzersiz IP: gösterilen cihazların TÜM görülen IP'lerinden → liste ile tutarlı.
        unique_ips=len({ip for d in devs for ip in (d['ips'] or d['ip'] or '').split(',') if ip}),
    )
    return render(request, 'dashboard/devices.html', context)


def _local_ip_note(ip):
    """ip (ipaddress nesnesi) yerel/özel ise açıklama döndür (gerçek WHOIS anlamsız —
    RIR yalnız 'özel alan' der), değilse None. Kendi dns-net /24'ümüz ayrıca belirtilir."""
    try:
        for sip in _server_ips():                       # konteynerin dns-net IP'leri (172.27.17.2…)
            if ip in ipaddress.ip_network(f"{sip}/24", strict=False):
                return ("Bu adres DNS sunucumuzun yerel ağına (dns-net) ait — genel WHOIS kaydı "
                        "YOKTUR. Bir yerel/konteyner cihazıdır.")
    except (ValueError, OSError):
        pass
    if ip.is_loopback:
        return "Loopback adresi (127.0.0.1 / ::1) — bu makinenin kendisi; WHOIS kaydı yoktur."
    if ip.is_link_local:
        return "Link-local adres (169.254.x / fe80::) — yerel cihaz; WHOIS kaydı yoktur."
    if ip.is_private:
        return ("Özel/yerel ağ adresi (RFC 1918) — genel WHOIS kaydı YOKTUR. "
                "Bu bir yerel cihazdır (LAN / VPN / konteyner).")
    if ip.is_reserved or ip.is_unspecified or ip.is_multicast:
        return "Özel-amaçlı / ayrılmış adres — genel WHOIS kaydı yoktur."
    return None


def _vcard_name(vcard):
    """RDAP jCard (vcardArray) içinden 'fn' (görünen ad) çıkar."""
    try:
        for item in vcard[1]:
            if item[0] == "fn":
                return item[3]
    except (TypeError, IndexError, KeyError):
        pass
    return ""


def _rdap_format(d, kind):
    """RDAP JSON → okunur özet metin. Eksik alanlar atlanır."""
    lines = []

    def add(k, v):
        if v:
            lines.append(f"{k}: {v}")

    if kind == "ip":
        rng = f"{d.get('startAddress', '')} – {d.get('endAddress', '')}".strip(" –")
        add("Aralık", rng)
        add("Ağ adı", d.get("name"))
        add("Handle", d.get("handle"))
        add("Tip", d.get("type"))
        add("Ülke", d.get("country"))
    else:
        add("Domain", d.get("ldhName") or d.get("handle"))
        add("Durum", ", ".join(d.get("status", []) or []))
    for e in (d.get("entities") or []):
        roles = ", ".join(e.get("roles", []) or [])
        name = _vcard_name(e.get("vcardArray")) or e.get("handle")
        add(f"İlgili ({roles})" if roles else "İlgili", name)
    for ev in (d.get("events") or []):
        add(ev.get("eventAction", "olay"), ev.get("eventDate"))
    for rm in (d.get("remarks") or []):
        desc = " ".join(rm.get("description", []) or [])
        if desc:
            lines.append(desc)
    return "\n".join(lines).strip() or None


def _rdap(query):
    """RDAP — WHOIS'in modern HTTPS(443) halefi. Port 43 kapalı sunucularda da çalışır.
    rdap.org bootstrap → doğru RIR/registry'ye yönlendirir (IP/domain otomatik)."""
    import httpx
    try:
        ipaddress.ip_address(query)
        kind = "ip"
    except ValueError:
        kind = "domain"
    with httpx.Client(timeout=6, follow_redirects=True) as c:
        r = c.get(f"https://rdap.org/{kind}/{query}",
                  headers={"accept": "application/rdap+json"})
    if r.status_code == 404:
        return None                       # kayıt yok
    r.raise_for_status()
    return _rdap_format(r.json(), kind)


def _whois(query):
    """IP YA DA alan adı için 2 adımlı WHOIS: whois.iana.org:43 sorumlu sunucuyu
    (RIR ya da TLD registry) döndürür → tam sorgu oraya yapılır. Ham metin döner.
    query çağırandan ÖNCE doğrulanmalı (IP/alan adı → enjeksiyon/SSRF önle).
    NOT: dış istek (IANA + ilgili RIR/registry, port 43)."""
    try:
        ipaddress.ip_address(query)
        iana_q = query                        # IP → doğrudan sorgula
    except ValueError:
        iana_q = query.rsplit('.', 1)[-1]     # alan adı → TLD ile sorumlu registry'yi bul

    def q(server, s):
        with socket.create_connection((server, 43), timeout=5) as sock:
            sock.sendall((s + '\r\n').encode('ascii', 'ignore'))
            data = b''
            while len(data) < 200_000:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
        return data.decode('utf-8', 'replace')

    top = q('whois.iana.org', iana_q)
    refer = ''
    for line in top.splitlines():
        low = line.lower()
        if low.startswith('refer:') or low.startswith('whois:'):   # IP→refer, TLD→whois
            refer = line.split(':', 1)[1].strip()
            break
    if refer and re.match(r'^[A-Za-z0-9.\-]+$', refer):   # sorumlu sunucu adı (temiz)
        try:
            return q(refer, query)
        except OSError:
            return top
    return top


def whois_lookup(request):
    """AJAX: bir IP ya da alan adı için WHOIS (yalnız yönetici). Girdi doğrulanır →
    enjeksiyon önlenir. Sync view → uvicorn threadpool'unda koşar (bloklayan soket
    olay döngüsünü tutmaz)."""
    uid = request.session.get('_auth_user_id')
    if not uid or not User.objects.filter(id=uid, is_superuser=True).exists():
        return JsonResponse({'error': 'auth'}, status=403)
    q = (request.GET.get('ip', '') or '').strip().lower().rstrip('.')
    try:
        ip_obj = ipaddress.ip_address(q)
    except ValueError:
        ip_obj = None
    if ip_obj is None and not _valid_domain(q):
        return JsonResponse({'error': 'Geçersiz IP / alan adı'}, status=400)
    if ip_obj is not None:                              # yerel/özel IP → dış sorguya GİTME
        note = _local_ip_note(ip_obj)
        if note:
            return JsonResponse({'query': q, 'whois': note, 'local': True})
    # Önce RDAP (HTTPS/443 — port 43 kapalı sunucularda da çalışır), sonra klasik WHOIS (43).
    text, err = None, None
    try:
        text = _rdap(q)
    except Exception as exc:   # noqa: BLE001
        err = type(exc).__name__
    if not text:
        try:
            text = _whois(q)
        except Exception as exc:   # noqa: BLE001 — dış sorgu hatası sayfayı bozmasın
            return JsonResponse({'error': 'RDAP/WHOIS başarısız — sunucudan GİDEN 443 (RDAP) '
                                          'ya da 43 (WHOIS) portu açık olmalı. '
                                          f'({err or type(exc).__name__})'}, status=502)
    return JsonResponse({'query': q, 'whois': (text or '').strip()[:8000] or '—'})


def device_record(request):
    """AJAX: sayfa açılışında + ~5 dk'lık arka plan beacon'ında JS'in gönderdiği cihaz
    verisini kaydeder. KİMLİK = istemcinin localStorage'daki KALICI id'si (farble-proof,
    oturumlar arası sabit; yoksa oturum-içi fallback) → aynı cihaz her seferinde AYNI
    satırı GÜNCELLER (ikiz yok). Açılışlar arası DEĞİŞEN fingerprint alanları `volatile`'a
    (tarayıcı rastgeliyor); görülen tüm IP'ler `ips`'e (VPN/ağ değişimi). Veri yalnız BU
    sunucuda kalır — same-origin, üçüncü tarafa hiçbir şey gitmez."""
    if request.method != 'POST':
        return JsonResponse({'error': 'method'}, status=405)
    if not request.session.get('_auth_user_id'):
        return JsonResponse({'error': 'auth'}, status=403)
    try:
        data = json.loads((request.body or b'').decode('utf-8') or '{}')
    except (ValueError, UnicodeDecodeError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    # Kimlik: localStorage'daki kalıcı id (sanitize). Yoksa (private mod / kapalı)
    # oturum-içi fallback → yine yenilemede aynı satır, ikiz olmaz.
    cid = re.sub(r'[^A-Za-z0-9._-]', '', str(data.get('devId') or ''))[:64]
    if not cid:
        cid = request.session.get('fp_client')
        if not cid:
            cid = uuid.uuid4().hex
            request.session['fp_client'] = cid

    ip = _client_ip(request)
    ua = (request.META.get('HTTP_USER_AGENT', '') or '')[:1000]
    parsed = parse_user_agent(ua)

    def s(key, n):
        v = data.get(key, '')
        return ('' if v is None else str(v))[:n]

    f = dict(
        screen=s('screen', 40), viewport=s('viewport', 40), timezone=s('timezone', 64),
        platform=s('platform', 64), languages=s('languages', 128), color_depth=s('colorDepth', 8),
        cpu=s('cpu', 8), memory=s('memory', 8), gpu=s('gpu', 200), canvas_hash=s('canvas', 64),
    )
    touch = bool(data.get('touch'))
    brave = bool(data.get('brave'))
    now = datetime.now(timezone.utc)
    username = request.session.get('panel_username', '')

    # Açılışlar arası DEĞİŞEN (tarayıcının rastgelediği) alanlar → koruma göstergesi
    _VOL = ('screen', 'timezone', 'platform', 'languages', 'color_depth',
            'cpu', 'memory', 'gpu', 'canvas_hash')
    # PII/tanımlayıcılar at-rest ŞİFRELİ (logcrypto/AES-SIV; anahtar yoksa düz geçer)
    _ENC = ('screen', 'viewport', 'timezone', 'platform', 'languages', 'gpu', 'canvas_hash')
    store = {k: (logcrypto.enc(v) if k in _ENC else v) for k, v in f.items()}
    try:
        obj, created = DeviceProfile.objects.get_or_create(
            fp_hash=cid,
            defaults=dict(
                ip=logcrypto.enc(ip), ips=logcrypto.enc(ip), user_agent=logcrypto.enc(ua),
                browser=parsed['browser'], os=parsed['os'], device=parsed['device'],
                touch=touch, brave=brave, username=username,
                extra=logcrypto.enc(json.dumps(data)[:4000]), last_seen=now, hits=1,
                fp_protected=(brave or bool(data.get('canvasProtected'))
                              or 'or similar' in f['gpu'].lower()),
                **store),
        )
        if not created:
            # oynak tespiti: saklanan (şifreli olabilir) değeri ÇÖZüp plain ile karşılaştır
            changed = {k for k in _VOL
                       if (logcrypto.dec(getattr(obj, k)) if k in _ENC else getattr(obj, k)) != f[k]}
            vol = set(filter(None, (obj.volatile or '').split(','))) | changed
            seen = set(filter(None, (logcrypto.dec(obj.ips) or '').split(',')))
            seen.add(ip)
            protected = (brave or bool(data.get('canvasProtected'))
                         or 'or similar' in f['gpu'].lower() or bool(vol))
            DeviceProfile.objects.filter(pk=obj.pk).update(
                last_seen=now, hits=F('hits') + 1, ip=logcrypto.enc(ip), username=username,
                ips=logcrypto.enc(','.join(sorted(seen)[:20])),
                volatile=','.join(sorted(vol))[:200],
                browser=parsed['browser'], os=parsed['os'], device=parsed['device'],
                touch=touch, brave=brave, fp_protected=protected, **store)
    except Exception:   # noqa: BLE001 — kayıt sayfayı bozmasın
        logger.exception('cihaz fingerprint kaydi yazilamadi')
        return JsonResponse({'ok': False}, status=200)
    return JsonResponse({'ok': True, 'new': created})


# PTR reverse-lookup önbelleği (süreç ömrü; hostname nadir değişir → kalıcı cache OK)
_ptr_cache: dict = {}


async def _reverse_lookups(ips):
    """IP listesi → {ip: hostname} (PTR). Önbellekli + kısa timeout + eşzamanlı;
    PTR yoksa/timeout olursa ''. Sayfayı yavaşlatmamak için budanmış çağrılır."""
    async def one(ip):
        if ip in _ptr_cache:
            return _ptr_cache[ip]
        host = ''
        try:
            res = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), timeout=1.2)
            host = (res[0] or '').rstrip('.')
        except Exception:   # noqa: BLE001 — PTR yok / timeout / hata → hostname yok
            host = ''
        _ptr_cache[ip] = host
        return host
    results = await asyncio.gather(*[one(ip) for ip in ips])
    return dict(zip(ips, results))


async def dns_devices(request):
    """DNS Cihazları: DNS SORGUSU yapan istemciler — IP + PTR hostname + kullanılan
    yöntem(ler) + sorgu sayısı + ilk/son görülme. (Panel-giriş 'Cihazlar'ından ayrı;
    bu DNS tarafı.) HTTP'siz olduğundan tanı IP/PTR/method ile sınırlı."""
    gate = _gate(request)
    if gate:
        return gate
    ctx = _base_ctx(request, 'dns_devices')
    try:
        devices = await db.get_dns_devices(limit=80)
    except Exception as e:   # noqa: BLE001 — DB erişilemezse sayfa yine açılsın
        ctx.update(devices=[], total=0, error=str(e))
        return render(request, 'dashboard/dns_devices.html', ctx)
    hosts = await _reverse_lookups([d['client_ip'] for d in devices[:60]])
    for d in devices:
        d['host'] = hosts.get(d['client_ip'], '')
    ctx.update(devices=devices, total=len(devices), error=None)
    return render(request, 'dashboard/dns_devices.html', ctx)


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
        allowed_host = request.POST.get('allowed_host', '').strip().lower().rstrip('.')
        if allowed_host and not _valid_domain(allowed_host):
            msg = ('error', 'Geçersiz DNS alan adı.')
        else:
            try:
                cfg = config_store.get_config()
                if cert_file:
                    cfg['cert_file'] = cert_file
                if key_file:
                    cfg['key_file'] = key_file
                if allowed_host:
                    cfg['allowed_host'] = allowed_host   # DoH/DoT SNI/Host + Kurulum adresleri
                config_store.write_config(cfg)
                msg = ('ok', "Kaydedildi — DNS alan adı Kurulum adreslerinde görünür; "
                             "sertifika değişikliği Sunucular'dan metodu kapatıp açınca yüklenir.")
            except Exception as exc:
                msg = ('error', _fail(exc))

    cfg = config_store.get_config()
    cert_file = cfg.get('cert_file', '')
    key_file = cfg.get('key_file', '')
    _ah = cfg.get('allowed_host', '')
    context.update(
        msg=msg, cert_file=cert_file, key_file=key_file,
        allowed_host='' if _ah == 'dns.example.com' else _ah,   # placeholder'ı boş göster
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


# Metot -> şemadaki STANDART port (domain URL'sinde bu port gizlenir).
_STD_PORT = {'udp': '53', 'doh': '443', 'dot': '853', 'doq': '853'}


def _connection_endpoints(cfg, cports, eports, domain, container_ip):
    """Açık yöntemlere göre bağlantı uç noktaları — iki erişim yolu:
      * domain (cihaz erişimi; host yayını / Cloudflare Tunnel): **DIŞ (external) port**
        gösterilir, standart ise (443/853/53) gizlenir → cihaz URL'si.
      * dns-net container IP (aynı ağdaki tünel/konteyner): **İÇ (container) port**.
    Şifreli yöntemler cert'i <b>domain</b>'e doğrular → IP ile bağlanmak cert-adı
    uyuşmazlığı verir; o yüzden şifreli metotta rastgele host IP'leri LİSTELENMEZ,
    yalnız domain + dns-net origin gösterilir."""
    def _dom(scheme, key, path):
        ep = eports.get(key, '')
        port = '' if ep == _STD_PORT[key] else ':' + ep
        return scheme + domain + port + path

    conn = []
    if cfg.get('udp'):
        items = []
        if domain:
            items.append(_dom('', 'udp', ''))                       # dış port (53 gizli)
        items.append(container_ip + ':' + cports['udp'])           # dns-net: iç port
        conn.append({'m': 'UDP', 'label': 'Düz DNS (UDP/TCP)', 'cert': False, 'items': items})
    enc = [
        ('doh', 'DoH', 'DNS-over-HTTPS', 'https://', '/dns-query'),
        ('dot', 'DoT', 'DNS-over-TLS', 'tls://', ''),
        ('doq', 'DoQ', 'DNS-over-QUIC', 'quic://', ''),
    ]
    for key, m, label, scheme, path in enc:
        if not cfg.get(key):
            continue
        items = []
        if domain:
            items.append(_dom(scheme, key, path))                  # cihaz URL'si (dış port)
        items.append(scheme + container_ip + ':' + cports[key] + path)  # dns-net origin (iç port)
        conn.append({'m': m, 'label': label, 'cert': True, 'items': items})
    return conn


async def guide(request):
    gate = _gate(request)
    if gate:
        return gate

    context = _base_ctx(request, 'guide')
    # Portlar + hangi metot açık → TEK kaynak config_store. İç (container) portlar
    # dns-net doğrudan erişim; dış (external) portlar cihaz/domain erişimi içindir.
    _sc = config_store.get_config()
    cports = {m: str(_sc['methods'][m]['container_port']) for m in METHODS}
    eports = {m: str(_sc['methods'][m]['external_port']) for m in METHODS}
    cfg = {m: _sc['methods'][m]['enabled'] for m in METHODS}

    try:
        req_host = request.get_host()
    except Exception:
        req_host = ''
    ips = _server_ips()

    domain = _sc.get('allowed_host', '').strip()
    if domain in ('localhost', '127.0.0.1', 'dns.example.com'):
        domain = ''

    container_ip = '172.27.17.2'
    context.update(
        ports=cports, eports=eports,
        conn=_connection_endpoints(cfg, cports, eports, domain, container_ip),
        req_host=req_host, server_ips=ips, domain=domain,
        subnet='172.27.17.0/24', host_ip='172.27.17.1', container_ip=container_ip,
        install_dir='/opt/DNS_RESOLVER', db_name='dns_db', db_user='dns_user',
    )
    return render(request, 'dashboard/guide.html', context)


# --------------------------------------------------------------------------- #
# Genel Ayarlar — geçmiş aç/kapa + önbellek (resolver ~10 sn'de uygular)
# --------------------------------------------------------------------------- #
async def test_upstreams_ajax(request):
    """AJAX: girilen upstream'leri test et → JSON döndür (sayfa YENİLENMEZ).
    Textarea'daki güncel (kaydedilmemiş olabilir) değerleri test eder."""
    if not request.session.get('_auth_user_id'):
        return JsonResponse({'error': 'auth'}, status=403)
    ups = [ln.strip() for ln in request.POST.get('upstreams', '').replace(',', '\n').splitlines() if ln.strip() and not ln.strip().startswith('#')]
    if not ups:
        return JsonResponse({'results': []})
    ups = ups[:20]   # üst sınır (uzun bekleme / kötüye kullanım önle)
    results = list(await asyncio.gather(*[asyncio.to_thread(test_upstream, u) for u in ups]))
    return JsonResponse({'results': results})


async def check_sources_ajax(request):
    """AJAX: eklenen liste URL'lerinin erişilebilirliğini kontrol et → JSON.
    Listeleri İNDİRMEZ; her URL'ye HEAD (gerekirse küçük GET) atar. Sayfa
    yenilenmez; sonuç satır satır işaretlenir."""
    if not request.session.get('is_admin'):
        return JsonResponse({'error': 'auth'}, status=403)
    try:
        sources = await db.get_sources()
    except Exception:  # noqa: BLE001
        return JsonResponse({'error': 'db'}, status=500)
    sources = sources[:80]   # üst sınır
    checks = await asyncio.gather(
        *[asyncio.to_thread(check_link, s['url']) for s in sources]
    )
    results = [
        {'id': s['id'], 'name': s['name'], 'url': s['url'], **c}
        for s, c in zip(sources, checks)
    ]
    return JsonResponse({'results': results})


async def backup_export(request):
    """Tüm panel ayarları + filtre/rewrite/zamanlama listelerini JSON olarak indir.
    DNS_LOG_KEY .env'de tutulur; yedekte YER ALMAZ (sır sızmaz)."""
    gate = _gate(request)
    if gate:
        return gate
    try:
        s, blocklist, allowlist, sources, rewrites, schedules, services = await asyncio.gather(
            db.get_settings(), db.get_blocklist(), db.get_allowlist(), db.get_sources(),
            db.get_rewrites(), db.get_schedules(), db.get_enabled_services())
    except Exception as exc:
        _fail(exc)
        return redirect('dashboard:settings')
    data = {
        'version': 1,
        'exported_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'app_settings': s,
        'blocklist': [b['domain'] for b in blocklist],
        'allowlist': [a['domain'] for a in allowlist],
        'sources': [{'name': x['name'], 'url': x['url'], 'enabled': bool(x['enabled'])} for x in sources],
        'rewrites': [{'domain': r['domain'], 'answer': r['answer'], 'enabled': bool(r['enabled'])} for r in rewrites],
        'schedules': [{'name': x['name'], 'days': x['days'], 'start_min': x['start_min'], 'end_min': x['end_min']} for x in schedules],
        'services': sorted(services),
    }
    fname = f"dns-panel-yedek-{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    resp = HttpResponse(json.dumps(data, ensure_ascii=False, indent=2), content_type='application/json; charset=utf-8')
    resp['Content-Disposition'] = f'attachment; filename="{fname}"'
    return resp


async def query_settings(request):
    """Sorgu/çözümleme ayarları — kendi sayfası (recursion, upstream, strateji, koşullu
    yönlendirme, bootstrap DNS). Upstream şema ön ekleri: udp:// tcp:// tls:// https:// quic://."""
    gate = _gate(request)
    if gate:
        return gate

    context = _base_ctx(request, 'query_settings')
    msg = None
    if request.method == 'POST':
        try:
            await db.set_setting('use_recursion', '1' if request.POST.get('use_recursion') else '0')
            await db.set_setting('dnssec', '1' if request.POST.get('dnssec') else '0')
            await db.set_setting('upstreams', request.POST.get('upstreams', '').strip())
            await db.set_setting('upstreams_secondary', request.POST.get('upstreams_secondary', '').strip())
            _strat = request.POST.get('upstream_strategy', 'sequential')
            await db.set_setting('upstream_strategy',
                                 _strat if _strat in ('sequential', 'parallel', 'fastest') else 'sequential')
            await db.set_setting('conditional_forwards', request.POST.get('conditional_forwards', '').strip())
            _bs = request.POST.get('bootstrap_dns', '').strip()
            if not _bs:
                await db.set_setting('bootstrap_dns', '')
                msg = ('ok', 'Sorgu ayarları kaydedildi — resolver ~10 sn içinde uygular.')
            else:
                try:
                    ipaddress.ip_address(_bs)
                    await db.set_setting('bootstrap_dns', _bs)
                    msg = ('ok', 'Sorgu ayarları kaydedildi — resolver ~10 sn içinde uygular.')
                except ValueError:
                    msg = ('error', f'Geçersiz bootstrap DNS IP: {_bs}')
        except Exception as exc:
            msg = ('error', _fail(exc))

    try:
        s = await db.get_settings()
    except Exception as exc:
        context.update(error=_fail(exc, 'Veritabanına erişilemedi.'), msg=msg)
        return render(request, 'dashboard/query_settings.html', context)

    context.update(
        msg=msg,
        use_recursion=s.get('use_recursion', '1') != '0',
        dnssec=s.get('dnssec', '0') != '0',
        upstreams=s.get('upstreams', ''),
        upstreams_secondary=s.get('upstreams_secondary', ''),
        upstream_strategy=s.get('upstream_strategy', 'sequential'),
        conditional_forwards=s.get('conditional_forwards', ''),
        bootstrap_dns=s.get('bootstrap_dns', ''),
        upstream_rows=_upstream_rows(s.get('upstreams', '')),
    )
    return render(request, 'dashboard/query_settings.html', context)


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
                _ups = [ln.strip() for ln in request.POST.get('upstreams', '').replace(',', '\n').splitlines() if ln.strip() and not ln.strip().startswith('#')]
                if _ups:
                    test_results = list(await asyncio.gather(*[asyncio.to_thread(test_upstream, u) for u in _ups]))
                    msg = ('ok', f'{len(_ups)} sunucu test edildi.')
                else:
                    msg = ('error', 'Test edilecek upstream yok — önce ekle.')
            elif 'import_backup' in request.POST:
                f = request.FILES.get('backup')
                data = None
                if not f:
                    msg = ('error', 'Dosya seçilmedi.')
                else:
                    try:
                        data = json.loads(f.read().decode('utf-8'))
                    except Exception:
                        msg = ('error', 'Geçersiz JSON yedek dosyası.')
                if isinstance(data, dict):
                    for k, v in (data.get('app_settings') or {}).items():
                        await db.set_setting(str(k), '' if v is None else str(v))
                    for d in (data.get('blocklist') or []):
                        dd = _norm_domain(str(d))
                        if _valid_block_domain(dd):
                            await db.add_block(dd)
                    for d in (data.get('allowlist') or []):
                        dd = _norm_domain(str(d))
                        if _valid_block_domain(dd):
                            await db.add_allow(dd)
                    for src in (data.get('sources') or []):
                        u = normalize_url(str(src.get('url', '')))
                        if u.startswith(('http://', 'https://')):
                            await db.add_source(src.get('name') or _auto_list_name(u), u)
                    for r in (data.get('rewrites') or []):
                        rd = _norm_rewrite_domain(str(r.get('domain', '')))
                        if _valid_rewrite_domain(rd) and _valid_rewrite_answer(str(r.get('answer', ''))):
                            await db.add_rewrite(rd, str(r['answer']).strip())
                    for sc in (data.get('schedules') or []):
                        try:
                            if sc.get('name'):
                                await db.set_schedule(str(sc['name']), str(sc.get('days', '')),
                                                      int(sc.get('start_min', 0)), int(sc.get('end_min', 0)))
                        except (ValueError, TypeError):
                            pass
                    _svc_by_name = {v['name']: v for v in SERVICES.values()}
                    for name in (data.get('services') or []):
                        svc = _svc_by_name.get(name)
                        if svc:
                            await db.set_service(svc['name'], svc['domains'], True)
                    msg = ('ok', 'Yedek geri yüklendi (mevcutlarla birleştirildi) — resolver ~15 sn içinde uygular.')
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
                    # Çözümleme ayarları (recursion/upstream/strateji/koşullu/bootstrap)
                    # artık ayrı "Sorgu Ayarları" sayfasında (views.query_settings).
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
        bootstrap_dns=s.get('bootstrap_dns', ''),
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
    ups = [ln.strip() for ln in upstreams_raw.replace(',', '\n').splitlines() if ln.strip() and not ln.strip().startswith('#')]
    stats = db.read_source_stats()
    return [{'up': u, 'avg': stats.get(u, {}).get('avg_ms'),
             'count': stats.get(u, {}).get('count', 0)} for u in ups]
