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
