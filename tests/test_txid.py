"""Güvenlik sertleştirme: DNS transaction id CSPRNG (off-path cache-poisoning
direnci) + bootstrap_resolve yanıt doğrulama (sahte/eski paketi reddet). Ağ yok —
soket mock'lanır."""
from dnslib import DNSRecord, RR, A, QTYPE

import doh_client
from servers.normal_udp import _new_question


def test_new_question_sets_id_in_range_and_varies():
    q = _new_question("example.com", "A")
    assert 0 <= q.header.id <= 65535
    assert str(q.q.qname).rstrip(".") == "example.com"
    ids = {_new_question("x.com", "A").header.id for _ in range(80)}
    assert len(ids) > 1                         # sabit değil (varyans var)


def _reply(qid, qname="dns.example.com", ip="9.9.9.9"):
    r = DNSRecord.question(qname, "A")
    r.header.id = qid
    r.header.qr = 1
    r.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=300))
    return r.pack()


class _FakeSock:
    """recvfrom, gönderilen sorgunun id'sine göre reply_fn ile yanıt üretir."""
    def __init__(self, reply_fn):
        self._reply_fn = reply_fn
        self._sent = None

    def settimeout(self, t):
        pass

    def sendto(self, data, addr):
        self._sent = data

    def recvfrom(self, n):
        qid = DNSRecord.parse(self._sent).header.id
        return self._reply_fn(qid), ("1.2.3.4", 53)

    def close(self):
        pass


def _patch(monkeypatch, reply_fn):
    monkeypatch.setattr(doh_client.socket, "socket", lambda af, kind: _FakeSock(reply_fn))


def test_bootstrap_accepts_matching_response(monkeypatch):
    _patch(monkeypatch, lambda qid: _reply(qid, "dns.example.com", "9.9.9.9"))
    assert doh_client.bootstrap_resolve("1.1.1.1", "dns.example.com") == "9.9.9.9"


def test_bootstrap_rejects_spoofed_id(monkeypatch):
    # DOĞRU soru adı ama YANLIŞ id (off-path sahte paket) → reddedilir
    _patch(monkeypatch, lambda qid: _reply((qid + 1) & 0xFFFF, "dns.example.com", "6.6.6.6"))
    assert doh_client.bootstrap_resolve("1.1.1.1", "dns.example.com") == "dns.example.com"


def test_bootstrap_rejects_wrong_qname(monkeypatch):
    # DOĞRU id ama YANLIŞ soru adı → reddedilir
    _patch(monkeypatch, lambda qid: _reply(qid, "evil.example.com", "6.6.6.6"))
    assert doh_client.bootstrap_resolve("1.1.1.1", "dns.example.com") == "dns.example.com"
