"""dashboard.useragent.parse_user_agent birim testleri (saf — Django gerektirmez).

Modülü dosya yolundan yükleriz: 'dashboard' paketi dns_resolver/ altında ve
pytest pythonpath'i repo köküdür; doğrudan yükleme Django kurulumundan bağımsız.
"""
import importlib.util
import pathlib

_UA = pathlib.Path(__file__).resolve().parents[1] / 'dns_resolver' / 'dashboard' / 'useragent.py'
_spec = importlib.util.spec_from_file_location('ua_mod', _UA)
_ua = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ua)
parse_user_agent = _ua.parse_user_agent


def test_chrome_windows_desktop():
    ua = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/120.0 Safari/537.36')
    r = parse_user_agent(ua)
    assert r == {'browser': 'Chrome', 'os': 'Windows 10/11', 'device': 'Masaüstü'}


def test_edge_before_chrome():
    # Edge UA'sinda 'Chrome/' de geçer → Edge önce yakalanmalı
    ua = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0')
    assert parse_user_agent(ua)['browser'] == 'Edge'


def test_safari_iphone_mobile():
    ua = ('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) '
          'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1')
    r = parse_user_agent(ua)
    assert r['os'] == 'iOS' and r['device'] == 'Mobil' and r['browser'] == 'Safari'


def test_firefox_linux():
    ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
    r = parse_user_agent(ua)
    assert r == {'browser': 'Firefox', 'os': 'Linux', 'device': 'Masaüstü'}


def test_android_chrome_mobile():
    ua = ('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36')
    r = parse_user_agent(ua)
    assert r['os'] == 'Android' and r['device'] == 'Mobil' and r['browser'] == 'Chrome'


def test_curl_and_empty():
    assert parse_user_agent('curl/8.4.0')['browser'] == 'curl'
    assert parse_user_agent('') == {'browser': 'Bilinmeyen', 'os': 'Bilinmeyen', 'device': 'Masaüstü'}
    assert parse_user_agent(None)['os'] == 'Bilinmeyen'
