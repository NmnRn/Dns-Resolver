"""DNSSEC doğrulama motoru (bağımsız, ağdan bağımsız — saf fonksiyonlar).

Bu modül YALNIZ kriptografik yapı taşlarıdır; ağ/resolver'a dokunmaz. `_resolve`
entegrasyonu + kök trust anchor ayrı adımdır (bkz. plan sonundaki NOT).

Zincir (RFC 4033-4035):
  1. Bir RRset'in RRSIG'ini, aynı bölgenin DNSKEY'iyle doğrula  -> verify_rrsig
  2. DNSKEY'in üst bölgedeki DS ile eşleştiğini doğrula         -> dnskey_to_ds
  3. Kök DNSKEY'i IANA trust anchor'ıyla doğrula                -> (anchor karşılaştırma)
  Sonuç: hepsi geçerse SECURE (AD biti); imzalı ama bozuksa BOGUS (SERVFAIL);
  DS zinciri yoksa INSECURE (passthrough).

Kanonik biçim (RFC 4034 §6): owner adları küçük harf + sıkıştırmasız; RRset,
kanonik RDATA'ya göre sıralı; TTL yerine RRSIG orig_ttl kullanılır.

Not: gömülü ad içeren tiplerde (NS/CNAME/MX/SOA) RDATA'daki adların küçültülmesi
tam uygulanmadı — A/AAAA/DNSKEY/DS/TXT gibi ad-içermeyen tiplerde tam doğrudur.
"""
import hashlib
import struct

from dnslib import DNSBuffer

# DNSSEC algoritma numaraları (IANA) — desteklenenler
ALG_RSASHA256 = 8
ALG_RSASHA512 = 10
ALG_ECDSAP256 = 13
ALG_ECDSAP384 = 14
ALG_ED25519 = 15

# DS digest tipleri
DS_SHA256 = 2
DS_SHA384 = 4
_DS_HASH = {DS_SHA256: hashlib.sha256, DS_SHA384: hashlib.sha384}


def encode_name(name: str) -> bytes:
    """Alan adını KANONİK wire biçimine çevir: küçük harf, uzunluk-önekli, sıkıştırmasız."""
    name = str(name).rstrip(".")
    out = b""
    if name:
        for label in name.split("."):
            lb = label.lower().encode("ascii", "ignore")
            out += bytes([len(lb)]) + lb
    return out + b"\x00"


def _rdata_bytes(rr) -> bytes:
    """Bir RR'nin RDATA'sını standalone (sıkıştırmasız) wire olarak döndür."""
    buf = DNSBuffer()
    rr.rdata.pack(buf)
    return buf.data


def key_tag(dnskey) -> int:
    """DNSKEY key tag'i (RFC 4034 Ek B) — DNSKEY RDATA baytları üzerinden."""
    rdata = struct.pack("!HBB", dnskey.flags, dnskey.protocol, dnskey.algorithm) + bytes(dnskey.key)
    ac = 0
    for i, b in enumerate(rdata):
        ac += b << 8 if (i & 1) == 0 else b
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF


def dnskey_to_ds(owner: str, dnskey, digest_type: int = DS_SHA256) -> bytes:
    """DNSKEY'den DS digest üret (RFC 4034 §5.1.4):
    digest = H( kanonik_owner_wire || DNSKEY_RDATA ). Üst bölgedeki DS ile karşılaştırılır."""
    h = _DS_HASH.get(digest_type)
    if h is None:
        raise ValueError(f"desteklenmeyen DS digest tipi: {digest_type}")
    rdata = struct.pack("!HBB", dnskey.flags, dnskey.protocol, dnskey.algorithm) + bytes(dnskey.key)
    return h(encode_name(owner) + rdata).digest()


def _signed_data(rrset_owner: str, rrset, rrsig) -> bytes:
    """RRSIG imza girdisini kur (RFC 4035 §5.3.2):
       RRSIG_RDATA(imza hariç) || sıralı kanonik RR'ler."""
    signed = struct.pack("!HBBIIIH",
                         rrsig.covered, rrsig.algorithm, rrsig.labels,
                         rrsig.orig_ttl, int(rrsig.sig_exp), int(rrsig.sig_inc),
                         rrsig.key_tag) + encode_name(str(rrsig.name))
    owner_wire = encode_name(rrset_owner)
    rows = []
    for rr in rrset:
        rd = _rdata_bytes(rr)
        rows.append(owner_wire
                    + struct.pack("!HHI", rr.rtype, rr.rclass, rrsig.orig_ttl)
                    + struct.pack("!H", len(rd)) + rd)
    rows.sort()                       # kanonik RRset sırası (RFC 4034 §6.3)
    return signed + b"".join(rows)


def verify_rrsig(rrset_owner: str, rrset, rrsig, dnskey) -> bool:
    """rrset'in imzasını (rrsig) dnskey ile doğrula. True=geçerli. Kripto/parse hatası
    -> False (fail-closed). Desteklenen alg: RSA/SHA-256,512 · ECDSA P-256,384 · Ed25519."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        data = _signed_data(rrset_owner, rrset, rrsig)
        alg = rrsig.algorithm
        key = bytes(dnskey.key)
        sig = bytes(rrsig.sig)

        if alg in (ALG_RSASHA256, ALG_RSASHA512):
            # RFC 3110: key = explen(1 ya da 3 bayt) || exponent || modulus
            if key[0] == 0:
                explen = int.from_bytes(key[1:3], "big"); idx = 3
            else:
                explen = key[0]; idx = 1
            e = int.from_bytes(key[idx:idx + explen], "big")
            n = int.from_bytes(key[idx + explen:], "big")
            pub = rsa.RSAPublicNumbers(e, n).public_key()
            digest = hashes.SHA256() if alg == ALG_RSASHA256 else hashes.SHA512()
            pub.verify(sig, data, padding.PKCS1v15(), digest)
            return True

        if alg in (ALG_ECDSAP256, ALG_ECDSAP384):
            half = len(sig) // 2
            r = int.from_bytes(sig[:half], "big")
            s = int.from_bytes(sig[half:], "big")
            der = encode_dss_signature(r, s)
            curve = ec.SECP256R1() if alg == ALG_ECDSAP256 else ec.SECP384R1()
            digest = hashes.SHA256() if alg == ALG_ECDSAP256 else hashes.SHA384()
            klen = len(key) // 2
            x = int.from_bytes(key[:klen], "big")
            y = int.from_bytes(key[klen:], "big")
            pub = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
            pub.verify(der, data, ec.ECDSA(digest))
            return True

        if alg == ALG_ED25519:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(key)
            pub.verify(sig, data)     # başarısızsa InvalidSignature fırlatır
            return True

        return False                  # desteklenmeyen algoritma → doğrulama yok
    except Exception:
        return False                  # fail-closed: imza tutmuyorsa/parse hatası → geçersiz
