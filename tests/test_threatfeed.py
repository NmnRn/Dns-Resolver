"""Tehdit/datacenter IP feed'i: CIDR parse + IP eşleşmesi (ağsız)."""
import threatfeed


def test_parse_cidrs_handles_formats():
    nets = threatfeed.parse_cidrs(
        "# yorum\n; yorum2\n1.2.3.0/24\n5.6.7.8 ; SBL123\n10.0.0.0/8\nbozuk-satir\n\n")
    assert [str(n) for n in nets] == ['1.2.3.0/24', '5.6.7.8/32', '10.0.0.0/8']


def test_in_feed_match():
    nets = threatfeed.parse_cidrs("1.2.3.0/24\n10.0.0.0/8\n")
    assert threatfeed.in_feed('1.2.3.9', nets) is True
    assert threatfeed.in_feed('10.255.1.1', nets) is True
    assert threatfeed.in_feed('8.8.8.8', nets) is False
    assert threatfeed.in_feed('gecersiz', nets) is False
