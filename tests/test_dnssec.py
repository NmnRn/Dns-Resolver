"""DNSSEC kripto motoru (servers/dnssec): kanonik ad, key_tag, DS digest ve RRSIG
doğrulama. RRSIG testleri kendi anahtarını üretip imzalar → dış vektör GEREKMEZ
(round-trip: doğru imza True, kurcalanan False). Ağ yok."""
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from dnslib import RR, RRSIG, DNSKEY, A, QTYPE

from servers import dnssec

OWNER = "example.com."


def _rrset(ip="1.2.3.4"):
    return [RR(rname=OWNER, rtype=QTYPE.A, rdata=A(ip), ttl=3600)]


def _rrsig(alg, kt, sig=b""):
    now = int(time.time())
    return RRSIG(covered=QTYPE.A, algorithm=alg, labels=2, orig_ttl=3600,
                 sig_exp=now + 86400, sig_inc=now - 3600, key_tag=kt,
                 name=OWNER, sig=sig)


def test_encode_name_canonical_lowercase():
    assert dnssec.encode_name("EXAMPLE.com.") == b"\x07example\x03com\x00"
    assert dnssec.encode_name(".") == b"\x00"
    assert dnssec.encode_name("a.b") == b"\x01a\x01b\x00"


def test_dnskey_to_ds_sha256_len():
    dk = DNSKEY(flags=257, protocol=3, algorithm=dnssec.ALG_ED25519, key=b"\x00" * 32)
    ds = dnssec.dnskey_to_ds(OWNER, dk, dnssec.DS_SHA256)
    assert len(ds) == 32                      # SHA-256


def test_ed25519_roundtrip():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    dk = DNSKEY(flags=257, protocol=3, algorithm=dnssec.ALG_ED25519, key=pub)
    kt = dnssec.key_tag(dk)
    rrset = _rrset()
    rrsig = _rrsig(dnssec.ALG_ED25519, kt)
    data = dnssec._signed_data(OWNER, rrset, rrsig)
    rrsig.sig = priv.sign(data)
    assert dnssec.verify_rrsig(OWNER, rrset, rrsig, dk) is True
    # kurcalanan RRset → doğrulama BAŞARISIZ
    assert dnssec.verify_rrsig(OWNER, _rrset("9.9.9.9"), rrsig, dk) is False


def test_ecdsa_p256_roundtrip():
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    dk = DNSKEY(flags=257, protocol=3, algorithm=dnssec.ALG_ECDSAP256, key=pub)
    kt = dnssec.key_tag(dk)
    rrset = _rrset()
    rrsig = _rrsig(dnssec.ALG_ECDSAP256, kt)
    data = dnssec._signed_data(OWNER, rrset, rrsig)
    der = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    rrsig.sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")   # DNSSEC ham r||s
    assert dnssec.verify_rrsig(OWNER, rrset, rrsig, dk) is True
    assert dnssec.verify_rrsig(OWNER, _rrset("8.8.8.8"), rrsig, dk) is False


def test_wrong_key_fails():
    priv = ed25519.Ed25519PrivateKey.generate()
    other = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    dk_wrong = DNSKEY(flags=257, protocol=3, algorithm=dnssec.ALG_ED25519, key=other)
    rrset = _rrset()
    rrsig = _rrsig(dnssec.ALG_ED25519, 0)
    rrsig.sig = priv.sign(dnssec._signed_data(OWNER, rrset, rrsig))
    assert dnssec.verify_rrsig(OWNER, rrset, rrsig, dk_wrong) is False


def test_unsupported_algorithm_returns_false():
    dk = DNSKEY(flags=257, protocol=3, algorithm=99, key=b"x" * 32)
    rrsig = _rrsig(99, 0, sig=b"y" * 64)
    assert dnssec.verify_rrsig(OWNER, _rrset(), rrsig, dk) is False


def test_dnskey_matches_ds():
    dk = DNSKEY(flags=257, protocol=3, algorithm=dnssec.ALG_ED25519, key=b"\x11" * 32)
    kt = dnssec.key_tag(dk)
    digest = dnssec.dnskey_to_ds(OWNER, dk, dnssec.DS_SHA256).hex()
    # büyük harf digest de eşleşmeli (case-insensitive)
    assert dnssec.dnskey_matches_ds(OWNER, dk, [(kt, dnssec.ALG_ED25519, dnssec.DS_SHA256, digest.upper())]) is not None
    # yanlış key_tag → eşleşme yok
    assert dnssec.dnskey_matches_ds(OWNER, dk, [(kt + 1, dnssec.ALG_ED25519, dnssec.DS_SHA256, digest)]) is None


def test_find_and_verify_roundtrip():
    priv = ed25519.Ed25519PrivateKey.generate()
    dk = DNSKEY(flags=257, protocol=3, algorithm=dnssec.ALG_ED25519, key=priv.public_key().public_bytes_raw())
    rrset = _rrset()
    rrsig = _rrsig(dnssec.ALG_ED25519, dnssec.key_tag(dk))
    rrsig.sig = priv.sign(dnssec._signed_data(OWNER, rrset, rrsig))
    assert dnssec.find_and_verify(OWNER, rrset, [rrsig], [dk]) is True
    other = DNSKEY(flags=257, protocol=3, algorithm=dnssec.ALG_ED25519,
                   key=ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    assert dnssec.find_and_verify(OWNER, rrset, [rrsig], [other]) is False


def test_root_anchor_present():
    assert 20326 in {a[0] for a in dnssec.ROOT_TRUST_ANCHORS}   # kök KSK-2017


# --- Sentetik imzalı hiyerarşi ile TAM zincir doğrulama (ağ yok) ------------ #
from dnslib import DS   # noqa: E402


def _keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    dk = DNSKEY(flags=257, protocol=3, algorithm=dnssec.ALG_ED25519,
                key=priv.public_key().public_bytes_raw())
    return priv, dk


def _sign(owner, rrset, priv, dk, covered, signer):
    now = int(time.time())
    rrsig = RRSIG(covered=covered, algorithm=dnssec.ALG_ED25519,
                  labels=owner.rstrip(".").count(".") + 1, orig_ttl=3600,
                  sig_exp=now + 86400, sig_inc=now - 3600, key_tag=dnssec.key_tag(dk),
                  name=signer, sig=b"")
    rrsig.sig = priv.sign(dnssec._signed_data(owner, rrset, rrsig))
    return rrsig


def _rr(name, rtype, rd):
    return RR(rname=name, rtype=rtype, rdata=rd, ttl=3600)


def _ds_rd(zone, key_child):
    # DS.digest RAW bayt (üretimde wire'dan böyle gelir; hex string verilirse dnslib
    # onu ASCII olarak paketler → yanlış).
    return DS(key_tag=dnssec.key_tag(key_child), algorithm=dnssec.ALG_ED25519,
              digest_type=dnssec.DS_SHA256,
              digest=dnssec.dnskey_to_ds(zone, key_child, dnssec.DS_SHA256))


def _hierarchy():
    """root(.) → tld. → example.tld. imzalı zincir + www.example.tld. A cevabı.
    fetch, RRset'i RR nesneleri olarak döndürür (üretimdeki gibi)."""
    (rp, rk), (tp, tk), (dp, dk) = _keypair(), _keypair(), _keypair()

    root_dk = [_rr(".", QTYPE.DNSKEY, rk)]
    tld_dk = [_rr("tld.", QTYPE.DNSKEY, tk)]
    dom_dk = [_rr("example.tld.", QTYPE.DNSKEY, dk)]
    ds_tld = [_rr("tld.", QTYPE.DS, _ds_rd("tld.", tk))]              # root imzalar
    ds_dom = [_rr("example.tld.", QTYPE.DS, _ds_rd("example.tld.", dk))]  # tld imzalar

    data = {
        (".", "DNSKEY"): (root_dk, [_sign(".", root_dk, rp, rk, QTYPE.DNSKEY, ".")]),
        ("tld.", "DNSKEY"): (tld_dk, [_sign("tld.", tld_dk, tp, tk, QTYPE.DNSKEY, "tld.")]),
        ("tld.", "DS"): (ds_tld, [_sign("tld.", ds_tld, rp, rk, QTYPE.DS, ".")]),
        ("example.tld.", "DNSKEY"): (dom_dk, [_sign("example.tld.", dom_dk, dp, dk, QTYPE.DNSKEY, "example.tld.")]),
        ("example.tld.", "DS"): (ds_dom, [_sign("example.tld.", ds_dom, tp, tk, QTYPE.DS, "tld.")]),
    }
    anchors = [(dnssec.key_tag(rk), dnssec.ALG_ED25519, dnssec.DS_SHA256,
                dnssec.dnskey_to_ds(".", rk, dnssec.DS_SHA256).hex())]
    answer = [_rr("www.example.tld.", QTYPE.A, A("1.2.3.4"))]
    answer_sig = _sign("www.example.tld.", answer, dp, dk, QTYPE.A, "example.tld.")
    keys = {"root": (rp, rk), "tld": (tp, tk), "dom": (dp, dk)}
    return data, anchors, answer, answer_sig, keys


def test_full_chain_secure():
    data, anchors, answer, sig, _ = _hierarchy()
    fetch = lambda n, t: data.get((n, t), ([], []))
    assert dnssec.validate_rrset("www.example.tld.", answer, [sig], fetch, anchors) == dnssec.SECURE


def test_full_chain_tampered_is_bogus():
    data, anchors, answer, sig, _ = _hierarchy()
    fetch = lambda n, t: data.get((n, t), ([], []))
    tampered = [_rr("www.example.tld.", QTYPE.A, A("9.9.9.9"))]     # imza cevaba uymaz
    assert dnssec.validate_rrset("www.example.tld.", tampered, [sig], fetch, anchors) == dnssec.BOGUS


def test_missing_ds_is_insecure():
    data, anchors, answer, sig, _ = _hierarchy()
    del data[("example.tld.", "DS")]          # güvenli delegasyon yok → insecure
    fetch = lambda n, t: data.get((n, t), ([], []))
    assert dnssec.validate_rrset("www.example.tld.", answer, [sig], fetch, anchors) == dnssec.INSECURE


def test_no_rrsig_is_insecure():
    fetch = lambda n, t: ([], [])
    answer = [_rr("x.tld.", QTYPE.A, A("1.2.3.4"))]
    assert dnssec.validate_rrset("x.tld.", answer, [], fetch) == dnssec.INSECURE


def test_broken_ds_link_is_bogus():
    data, anchors, answer, sig, keys = _hierarchy()
    tp, tk = keys["tld"]
    _, wrong = _keypair()                     # DS geçerli imzalı AMA yanlış anahtara işaret ediyor
    bad_ds = [_rr("example.tld.", QTYPE.DS, _ds_rd("example.tld.", wrong))]
    data[("example.tld.", "DS")] = (bad_ds, [_sign("example.tld.", bad_ds, tp, tk, QTYPE.DS, "tld.")])
    fetch = lambda n, t: data.get((n, t), ([], []))
    assert dnssec.validate_rrset("www.example.tld.", answer, [sig], fetch, anchors) == dnssec.BOGUS


# --- Resolver entegrasyonu (DNSCore.validate + resolve hook) ----------------
def test_core_validate_uses_engine(monkeypatch):
    from servers.normal_udp import DNSCore
    data, anchors, answer, sig, _ = _hierarchy()
    monkeypatch.setattr(dnssec, "ROOT_TRUST_ANCHORS", anchors)
    core = DNSCore(db_manager=None)
    core._dnssec_fetch = lambda n, t: (answer, [sig]) if (n, t) == ("www.example.tld.", "A") else data.get((n, t), ([], []))
    assert core.validate("www.example.tld.", "A") == dnssec.SECURE
    core._dnssec_fetch = lambda n, t: ([], [])          # cevap/imza yok
    assert core.validate("www.example.tld.", "A") == dnssec.INSECURE


def test_resolve_dnssec_hook_bogus_and_secure():
    from servers.normal_udp import DNSCore
    from dnslib import RCODE
    core = DNSCore(db_manager=None)
    core.dnssec = True
    core._resolve = lambda *a, **k: (RCODE.NOERROR, ["rr"])
    core.validate = lambda q, t: dnssec.BOGUS
    ds = ["off"]
    rc, recs = core.resolve("x.com.", "A", 0, ["—"], ds)
    assert rc == RCODE.SERVFAIL and recs == [] and ds[0] == "bogus"   # bogus → SERVFAIL
    core.validate = lambda q, t: dnssec.SECURE
    ds = ["off"]
    rc, recs = core.resolve("x.com.", "A", 0, ["—"], ds)
    assert rc == RCODE.NOERROR and recs == ["rr"] and ds[0] == "secure"

    core.dnssec = False                                  # kapalıyken validate çağrılmaz
    called = []
    core.validate = lambda q, t: called.append(1) or dnssec.SECURE
    ds = ["off"]
    core.resolve("x.com.", "A", 0, ["—"], ds)
    assert called == [] and ds[0] == "off"
