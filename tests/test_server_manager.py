"""ServerManager.reconcile: aç/kapa + iç-port değişiminde yeniden başlatma +
ön koşul (cert) yoksa 'failed' işaretleme + geriye dönük düz-bool desteği."""
import asyncio

from servers.manager import ServerManager


def _starter(name, events):
    async def start():
        events.append(("start", name))
        def stop():
            events.append(("stop", name))
        return stop
    return start


def test_start_stop_and_port_change():
    ev = []
    mgr = ServerManager({"udp": _starter("udp", ev), "doh": _starter("doh", ev)})

    async def scenario():
        await mgr.reconcile({"udp": {"enabled": True, "container_port": 5300},
                             "doh": {"enabled": False, "container_port": 44300}})
        assert "udp" in mgr.running and "doh" not in mgr.running
        # iç port değişimi → yeniden başlat
        await mgr.reconcile({"udp": {"enabled": True, "container_port": 5301},
                             "doh": {"enabled": False, "container_port": 44300}})
        # doh aç, sonra udp kapat
        await mgr.reconcile({"udp": {"enabled": True, "container_port": 5301},
                             "doh": {"enabled": True, "container_port": 44300}})
        assert "doh" in mgr.running
        await mgr.reconcile({"udp": {"enabled": False, "container_port": 5301},
                             "doh": {"enabled": True, "container_port": 44300}})
        assert "udp" not in mgr.running

    asyncio.run(scenario())
    assert ev.count(("start", "udp")) == 2   # ilk açılış + port değişince
    assert ev.count(("stop", "udp")) == 2    # port değişince + kapatınca
    assert ("start", "doh") in ev


def test_precondition_missing_marks_failed_and_not_retried():
    ev = []

    async def none_starter():
        ev.append("try")
        return None  # cert yok

    mgr = ServerManager({"dot": none_starter})

    async def scenario():
        await mgr.reconcile({"dot": {"enabled": True, "container_port": 8853}})
        assert "dot" not in mgr.running and "dot" in mgr.failed
        await mgr.reconcile({"dot": {"enabled": True, "container_port": 8853}})
        assert "dot" not in mgr.running

    asyncio.run(scenario())
    assert ev.count("try") == 1   # failed → her turda tekrar denemez


def test_backward_compat_plain_bool():
    ev = []
    mgr = ServerManager({"udp": _starter("udp", ev)})
    asyncio.run(mgr.reconcile({"udp": True}))
    assert "udp" in mgr.running


def test_stop_all():
    ev = []
    mgr = ServerManager({"udp": _starter("udp", ev), "doh": _starter("doh", ev)})
    asyncio.run(mgr.reconcile({"udp": {"enabled": True, "container_port": 5300},
                               "doh": {"enabled": True, "container_port": 44300}}))
    mgr.stop_all()
    assert not mgr.running
    assert ("stop", "udp") in ev and ("stop", "doh") in ev
