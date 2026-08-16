"""doh_client: IP tespiti + bootstrap URL yeniden yazma.

_bootstrap_target güvenlik açısından önemli: host'u IP ile değiştirir ama yol/port/
query'yi korur (Host header + SNI orijinal ad ayrıca ayarlanır → TLS doğrulaması
doğru host'a yapılır).
"""
from doh_client import _is_ip, _bootstrap_target


def test_is_ip():
    assert _is_ip('1.2.3.4')
    assert _is_ip('9.9.9.9')
    assert _is_ip('2001:db8::1')
    assert not _is_ip('dns.google')
    assert not _is_ip('cloudflare-dns.com')
    assert not _is_ip('')


def test_bootstrap_target_rewrites_host_keeps_path_query():
    assert _bootstrap_target('https://cloudflare-dns.com/dns-query?dns=AAA', '1.2.3.4') == \
        'https://1.2.3.4/dns-query?dns=AAA'


def test_bootstrap_target_keeps_port():
    assert _bootstrap_target('https://dns.google:8443/dns-query', '5.6.7.8') == \
        'https://5.6.7.8:8443/dns-query'


def test_bootstrap_target_no_query():
    assert _bootstrap_target('https://dns.quad9.net/dns-query', '9.9.9.9') == \
        'https://9.9.9.9/dns-query'
