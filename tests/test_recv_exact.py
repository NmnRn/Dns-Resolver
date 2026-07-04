"""normal_udp._recv_exact: TCP'de parça parça gelen veriyi tam n bayt okur."""
import pytest

from servers.normal_udp import _recv_exact


class ChunkedSock:
    """recv() her çağrıda en fazla max_chunk bayt döndürür (kısa okuma taklidi)."""

    def __init__(self, data, max_chunk=1):
        self.data = bytes(data)
        self.pos = 0
        self.max_chunk = max_chunk

    def recv(self, n):
        take = min(n, self.max_chunk, len(self.data) - self.pos)
        chunk = self.data[self.pos:self.pos + take]
        self.pos += take
        return chunk


def test_assembles_across_short_reads():
    sock = ChunkedSock(b"abcdef", max_chunk=1)  # bayt bayt gelir
    assert _recv_exact(sock, 6) == b"abcdef"


def test_reads_exactly_n_not_more():
    sock = ChunkedSock(b"abcdefghij", max_chunk=100)  # hepsi hazır
    assert _recv_exact(sock, 4) == b"abcd"


def test_raises_on_early_close():
    sock = ChunkedSock(b"abc", max_chunk=10)  # 3 bayt var, 6 istiyoruz
    with pytest.raises(ConnectionError):
        _recv_exact(sock, 6)
