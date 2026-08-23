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
import time

from dnslib import DNSBuffer, QTYPE

# DNSSEC algoritma numaraları (IANA) — desteklenenler
ALG_RSASHA256 = 8
ALG_RSASHA512 = 10
ALG_ECDSAP256 = 13
ALG_ECDSAP384 = 14
ALG_ED25519 = 15

# RRSIG geçerlilik penceresi (RFC 4035 §5.3.1) için saat kayması toleransı (sn).
# NTP'siz hafif drift TÜM imzaları kırmasın; süresi gerçekten dolmuş (saatlerce)
# imzalar yine yakalanır. Saat çok yanlışsa imzalı alanlar SERVFAIL olur → NTP şart.
RRSIG_SKEW = 300

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
        # Geçerlilik penceresi (RFC 4035 §5.3.1): şu an [inception, expiration] dışındaysa
        # imza GEÇERSİZ — süresi dolmuş ya da henüz başlamamış. (Kripto doğru olsa bile.)
        now = time.time()
        if not (int(rrsig.sig_inc) - RRSIG_SKEW <= now <= int(rrsig.sig_exp) + RRSIG_SKEW):
            return False
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
# IANA kök trust anchor'ları (DS kaydı olarak). Her ikisi de algoritma 8
# (RSASHA256), digest tipi 2 (SHA-256). Kök herhangi biriyle doğrulanabilir.
# ⚠️ Kaynak: IANA root-anchors.xml (https://data.iana.org/root-anchors/).
#    KSK rollover'da DEĞİŞİR — üretimde buradan doğrula/güncelle.
#    (tag, alg, digest_type, digest_hex)
ROOT_TRUST_ANCHORS = [
    # KSK-2017 (validFrom 2017-02-02) — hâlâ yayında.
    (20326, 8, 2, "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d"),
    # KSK-2024 (validFrom 2024-07-18) — bir sonraki rollover için yayınlanan yedek.
    (38696, 8, 2, "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16"),
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


# --- Yokluk doğrulama: NSEC / NSEC3 (RFC 4034/4035, RFC 5155) ---------------- #
# NXDOMAIN ve NODATA cevaplarının kriptografik kanıtı. Fail-safe: bölge imzasız
# ya da kanıt belirsizse INSECURE (NXDOMAIN kırılmaz); imzalı bölgede NSEC/NSEC3
# imzası GEÇERSİZse BOGUS (tahrifat); kanıt tam tutarsa SECURE.

def _canon_labels(name):
    """Kanonik sıralama anahtarı (RFC 4034 §6.1): küçük harf label'lar, EN
    ÖNEMSİZDEN (sağdan) sola. Python tuple karşılaştırması bu sırayı korur
    (kısa olan, ortak önekte önce gelir)."""
    n = str(name).rstrip(".").lower()
    if not n:
        return ()
    labels = n.split(".")
    labels.reverse()
    return tuple(labels)


def _name_eq(a, b):
    return _canon_labels(a) == _canon_labels(b)


def _nsec_covers(owner, next_name, qname):
    """NSEC (owner..next) qname'i KAPSIYOR mu → qname yok demektir: owner < qname < next.
    Zincirin son NSEC'i next=apex ile sarar (next <= owner) → owner < qname VEYA qname < next."""
    o = _canon_labels(owner); nx = _canon_labels(next_name); q = _canon_labels(qname)
    if nx <= o:                              # sarma (zincir sonu)
        return q > o or q < nx
    return o < q < nx


def _ancestors(name, zone):
    """qname'in ata adları: en uzundan (bir üst) zone'a kadar (zone dahil)."""
    n = str(name).rstrip(".").lower(); z = str(zone).rstrip(".").lower()
    labels = n.split(".") if n else []
    out = []
    for i in range(1, len(labels) + 1):
        a = ".".join(labels[i:])
        out.append((a + ".") if a else ".")
        if a == z:
            break
    return out


def _is_ancestor_or_eq(a, name):
    a = str(a).rstrip(".").lower(); name = str(name).rstrip(".").lower()
    if not a:
        return True                          # kök herkesin atasıdır
    return a == name or name.endswith("." + a)


def _closest_encloser(qname, owner, nextn, zone):
    """qname'in en yakın kapsayıcısı: qname'in atalarından, kapsayan NSEC'in
    owner/next'iyle ortak EN UZUN olanı (yoksa zone)."""
    for a in _ancestors(qname, zone):
        if _is_ancestor_or_eq(a, owner) or _is_ancestor_or_eq(a, nextn):
            return a
    return zone if str(zone).endswith(".") else str(zone) + "."


def _nsec_proves(qname, qtype, zone, proofs):
    """NSEC kayıtları qname/qtype yokluğunu gösteriyor mu?"""
    nsecs = [(p["owner"], p["next"], p["types"]) for p in proofs if p["kind"] == "nsec"]
    if not nsecs:
        return False
    # NODATA: owner == qname ve qtype (+CNAME) bitmap'te YOK
    for owner, _nxt, types in nsecs:
        if _name_eq(owner, qname) and qtype not in types and "CNAME" not in types:
            return True
    # NXDOMAIN: (a) qname'i kapsayan NSEC + (b) *.CE'yi kapsayan/eşleşen NSEC
    covering = None
    for owner, nxt, _types in nsecs:
        if _nsec_covers(owner, nxt, qname):
            covering = (owner, nxt); break
    if not covering:
        return False
    ce = _closest_encloser(qname, covering[0], covering[1], zone)
    wildcard = "*." + ce.lstrip(".") if ce not in (".", "") else "*."
    for owner, nxt, types in nsecs:
        if _name_eq(owner, wildcard) and qtype not in types:
            return True                      # wildcard var, tipi yok (wildcard-NODATA)
        if _nsec_covers(owner, nxt, wildcard):
            return True                      # wildcard yok
    return False


# NSEC3: base32hex (RFC 4648) + SHA-1 hash (RFC 5155 §5)
_B32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"


def _b32hex(data):
    """base32hex kodla (padsız, büyük harf)."""
    bits = 0; val = 0; out = []
    for byte in data:
        val = (val << 8) | byte; bits += 8
        while bits >= 5:
            bits -= 5; out.append(_B32HEX[(val >> bits) & 0x1F])
    if bits:
        out.append(_B32HEX[(val << (5 - bits)) & 0x1F])
    return "".join(out)


def nsec3_hash(name, salt, iterations):
    """NSEC3 hash (RFC 5155 §5): H = SHA-1(name_wire || salt); iterations kez
    H = SHA-1(H || salt). Dönüş: base32hex (büyük harf). Yalnız alg=1 (SHA-1)."""
    digest = hashlib.sha1(encode_name(name) + salt).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()
    return _b32hex(digest)


def _type_name(t):
    try:
        return QTYPE[t]
    except Exception:
        return f"TYPE{t}"


def _parse_type_bitmap(data):
    """NSEC/NSEC3 tip bitmap → tip adları kümesi (RFC 4034 §4.1.2)."""
    types = set(); i = 0
    while i + 2 <= len(data):
        window = data[i]; blen = data[i + 1]; i += 2
        block = data[i:i + blen]; i += blen
        for bi, byte in enumerate(block):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    types.add(_type_name(window * 256 + bi * 8 + bit))
    return types


def parse_nsec3(raw):
    """NSEC3 RDATA ham baytlarını çöz → dict(alg,flags,iterations,salt,next_b32,types)."""
    raw = bytes(raw)
    alg = raw[0]; flags = raw[1]
    iterations = int.from_bytes(raw[2:4], "big")
    slen = raw[4]; i = 5
    salt = raw[i:i + slen]; i += slen
    hlen = raw[i]; i += 1
    next_hashed = raw[i:i + hlen]; i += hlen
    return {"alg": alg, "flags": flags, "iterations": iterations, "salt": salt,
            "next_b32": _b32hex(next_hashed), "types": _parse_type_bitmap(raw[i:])}


def _nsec3_covers(owner_h, next_h, target_h):
    """NSEC3 (owner_h..next_h) target hash'ini KAPSIYOR mu (base32hex, büyük harf)."""
    o = owner_h.upper(); n = next_h.upper(); t = target_h.upper()
    if n <= o:                               # sarma
        return t > o or t < n
    return o < t < n


def _next_closer(qname, ce):
    """ce'nin bir label altındaki, qname'in atası olan ad (next closer name)."""
    q = str(qname).rstrip(".").lower(); c = str(ce).rstrip(".").lower()
    if c and not (q == c or q.endswith("." + c)):
        return None
    prefix = q[:-(len(c) + 1)] if c else q   # ce'den önceki kısım
    plabels = prefix.split(".") if prefix else []
    if not plabels:
        return None
    tail = ("." + c) if c else ""
    return plabels[-1] + tail + "."


def _nsec3_proves(qname, qtype, zone, proofs):
    """NSEC3 kayıtları qname/qtype yokluğunu gösteriyor mu? (opt-out → güvenli değil)"""
    items = []
    for p in proofs:
        if p["kind"] != "nsec3" or not p.get("parsed"):
            continue
        pa = p["parsed"]
        if pa["alg"] != 1:                   # yalnız SHA-1 destekli → belirsiz
            return False
        owner_h = str(p["owner"]).split(".", 1)[0].upper()
        items.append((owner_h, pa))
    if not items:
        return False
    salt = items[0][1]["salt"]; iters = items[0][1]["iterations"]

    def H(name):
        return nsec3_hash(name, salt, iters)

    # NODATA: qname hash'iyle EŞLEŞEN NSEC3 + qtype yok
    hq = H(qname)
    for oh, pa in items:
        if oh == hq and qtype not in pa["types"] and "CNAME" not in pa["types"]:
            return True
    # NXDOMAIN: closest encloser kanıtı (3 NSEC3)
    ce = None
    for a in _ancestors(qname, zone):        # en uzundan
        ha = H(a)
        if any(oh == ha for oh, _ in items):
            ce = a; break
    if ce is None:
        return False
    nc = _next_closer(qname, ce)
    if nc is None:
        return False
    hnc = H(nc); covered = False
    for oh, pa in items:
        if _nsec3_covers(oh, pa["next_b32"], hnc):
            if pa["flags"] & 0x01:           # opt-out → güvenli değil (INSECURE)
                return False
            covered = True; break
    if not covered:
        return False
    wc = ("*." + ce.rstrip(".")) if ce not in (".", "") else "*"
    hw = H(wc)
    for oh, pa in items:
        if oh == hw and qtype not in pa["types"]:
            return True
        if _nsec3_covers(oh, pa["next_b32"], hw):
            return True
    return False


def validate_denial(qname, qtype, zone, proofs, fetch, anchors=None):
    """NXDOMAIN/NODATA cevabının DNSSEC yokluk durumu: SECURE / INSECURE / BOGUS.
    proofs: authority'den çıkarılan NSEC/NSEC3 kümeleri; her biri
      {'kind','owner','rrset','rrsigs', + NSEC:'next','types' / NSEC3:'parsed'}.
    Karar: bölge güvenli değil / kanıt yok / kanıt belirsiz → INSECURE (fail-safe);
    bölge güvenli AMA NSEC/NSEC3 imzası tutmuyor → BOGUS; kanıt tam → SECURE."""
    if not proofs or not zone:
        return INSECURE
    st, keys = get_zone_dnskeys(zone, fetch, anchors)
    if st != SECURE:
        return st                            # imzasız → INSECURE; zincir bogus → BOGUS
    # 1) Her NSEC/NSEC3 RRset'inin imzasını bölge anahtarıyla doğrula (fail-closed)
    for p in proofs:
        if not p.get("rrsigs") or not find_and_verify(p["owner"], p["rrset"], p["rrsigs"], keys):
            return BOGUS                     # imzalı bölgede yokluk imzası yok/geçersiz → tahrifat
    # 2) Kanıt gerçekten qname/qtype yokluğunu gösteriyor mu?
    kind = proofs[0]["kind"]
    try:
        ok = _nsec_proves(qname, qtype, zone, proofs) if kind == "nsec" \
            else _nsec3_proves(qname, qtype, zone, proofs)
    except Exception:
        ok = False
    return SECURE if ok else INSECURE        # kanıt doğrulanamadıysa güvenli tarafta INSECURE
