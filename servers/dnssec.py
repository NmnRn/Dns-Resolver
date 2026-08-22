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


# --- Trust anchor + zincir bağları ------------------------------------------ #
# IANA kök trust anchor (DS kaydı olarak). Kök KSK-2017: key tag 20326,
# algoritma 8 (RSASHA256), digest tipi 2 (SHA-256).
# ⚠️ Kaynak: IANA root-anchors.xml (https://data.iana.org/root-anchors/).
#    KSK rollover'da DEĞİŞİR — üretimde buradan doğrula/güncelle (yeni KSK-2024
#    key tag 38696 eklendiğinde listeye ekle). (tag, alg, digest_type, digest_hex)
ROOT_TRUST_ANCHORS = [
    (20326, 8, 2, "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d"),
]


def dnskey_matches_ds(owner, dnskey, ds_list):
    """dnskey'in DS özeti, ds_list'teki (tag, alg, digest_type, digest_hex) kayıtlarından
    biriyle eşleşiyor mu? Üst bölge DS'i ↔ alt bölge DNSKEY bağını doğrular.
    Eşleşen DS 4'lüsünü döner, yoksa None."""
    kt = key_tag(dnskey)
    for entry in ds_list:
        tag, alg, dtype, digest_hex = entry
        if tag != kt or alg != dnskey.algorithm:
            continue
        try:
            calc = dnskey_to_ds(owner, dnskey, dtype).hex()
        except ValueError:
            continue
        if calc == digest_hex.lower():
            return entry
    return None


def find_and_verify(owner, rrset, rrsigs, dnskeys):
    """rrset'i, rrsigs içindeki bir RRSIG + dnskeys içindeki EŞLEŞEN (key_tag+alg)
    DNSKEY ile doğrula. Herhangi bir (rrsig, dnskey) çifti tutarsa True (fail-closed)."""
    for rrsig in rrsigs:
        for dk in dnskeys:
            if key_tag(dk) == rrsig.key_tag and dk.algorithm == rrsig.algorithm:
                if verify_rrsig(owner, rrset, rrsig, dk):
                    return True
    return False


# --- Zincir doğrulama (kökten aşağı) ---------------------------------------- #
SECURE = "secure"      # imza zinciri kökten doğrulandı → AD biti
INSECURE = "insecure"  # imzasız bölge (DS yok) → normal döner, AD yok
BOGUS = "bogus"        # imzalı AMA doğrulanamadı → SERVFAIL


def _parent_zone(zone):
    z = zone.rstrip(".")
    if not z or "." not in z:
        return "."
    return z.split(".", 1)[1] + "."


def _ds_digest_hex(ds):
    d = ds.digest
    return d.hex() if isinstance(d, (bytes, bytearray)) else str(d).replace(" ", "").lower()


def get_zone_dnskeys(zone, fetch, anchors=None, _depth=0):
    """zone apex'inin DOĞRULANMIŞ DNSKEY'lerini döndür (kökten zincirle).
    Dönüş: (durum, dnskeys). fetch(name, rtype) -> (rrset, rrsigs).
    Kök: DNSKEY'i trust anchor DS'iyle doğrular; alt bölgeler: DS'i parent DNSKEY
    ile doğrular + DNSKEY'in DS ile eşleşen KSK'sıyla imzasını denetler."""
    anchors = anchors if anchors is not None else ROOT_TRUST_ANCHORS
    zone = zone if zone.endswith(".") else zone + "."
    if _depth > 20:
        return BOGUS, []

    # fetch RRset'i RR nesnesi listesi olarak döndürür; DNSKEY/DS "RD" alanları rr.rdata'da.
    dnskey_rrs, dk_sigs = fetch(zone, "DNSKEY")
    if not dnskey_rrs:
        return INSECURE, []                      # bölge imzalı değil gibi
    dnskeys = [rr.rdata for rr in dnskey_rrs]    # DNSKEY RD'leri (key/flags/algorithm)

    if zone == ".":
        ds_list = list(anchors)
    else:
        ds_rrs, ds_sigs = fetch(zone, "DS")      # child'ın DS'i parent'ta yayınlanır
        if not ds_rrs:
            return INSECURE, []                  # güvenli delegasyon yok → insecure
        st, parent_keys = get_zone_dnskeys(_parent_zone(zone), fetch, anchors, _depth + 1)
        if st != SECURE:
            return (BOGUS if st == BOGUS else INSECURE), []
        if not find_and_verify(zone, ds_rrs, ds_sigs, parent_keys):
            return BOGUS, []                     # DS RRSIG parent'la tutmuyor
        ds_list = [(d.rdata.key_tag, d.rdata.algorithm, d.rdata.digest_type, _ds_digest_hex(d.rdata))
                   for d in ds_rrs]

    ksks = [dk for dk in dnskeys if dnskey_matches_ds(zone, dk, ds_list)]
    if not ksks:
        return BOGUS, []                         # hiçbir DNSKEY DS ile eşleşmiyor
    if not find_and_verify(zone, dnskey_rrs, dk_sigs, ksks):
        return BOGUS, []                         # DNSKEY RRset öz-imzası tutmuyor
    return SECURE, dnskeys                        # doğrulanmış DNSKEY RD listesi


def validate_rrset(owner, rrset, rrsigs, fetch, anchors=None):
    """Bir RRset'in DNSSEC durumu: SECURE / INSECURE / BOGUS.
    owner: RRset sahibi ad; rrsigs: bu RRset'i kaplayan RRSIG'ler; fetch: zincir çekici."""
    if not rrsigs:
        return INSECURE                          # imza yok → doğrulanamaz (insecure)
    zone = str(rrsigs[0].name)                   # imzalayan bölge (RRSIG signer name)
    st, keys = get_zone_dnskeys(zone, fetch, anchors)
    if st != SECURE:
        return st
    return SECURE if find_and_verify(owner, rrset, rrsigs, keys) else BOGUS
