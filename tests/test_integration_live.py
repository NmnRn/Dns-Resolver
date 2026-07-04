"""Opt-in canlı entegrasyon testi: gerçek ağ üzerinden recursive çözümleme.

Varsayılan olarak ATLANIR. Çalıştırmak için:
    DNS_INTEGRATION=1 ./.venv/bin/pytest tests/test_integration_live.py
"""
import os

import pytest
from dnslib import QTYPE, RCODE

from servers.normal_udp import DNSCore

pytestmark = pytest.mark.skipif(
    os.getenv("DNS_INTEGRATION") != "1",
    reason="ağ gerektirir; DNS_INTEGRATION=1 ile çalıştır",
)


def test_resolve_example_com_a():
    core = DNSCore()
    rcode, records = core.resolve("example.com.", "A")
    assert rcode == RCODE.NOERROR
    assert any(QTYPE[r.rtype] == "A" for r in records)
