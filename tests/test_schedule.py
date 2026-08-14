"""Zamanlanmış engelleme zaman mantığı: db_core.schedule_active (saf fonksiyon).

days: haftanın günleri (Pzt=0…Paz=6); start/end: gün içi dakika (yerel);
end < start ise pencere gece yarısını aşar.
"""
from db_ops.db_core import schedule_active

WEEKDAYS = frozenset({0, 1, 2, 3, 4})   # Pzt–Cum
NINE, FIVE = 9 * 60, 17 * 60             # 09:00, 17:00


def test_within_window():
    assert schedule_active(WEEKDAYS, NINE, FIVE, 0, 12 * 60)      # Pzt 12:00


def test_start_boundary_inclusive():
    assert schedule_active(WEEKDAYS, NINE, FIVE, 0, NINE)         # 09:00 tam → aktif


def test_end_boundary_exclusive():
    assert not schedule_active(WEEKDAYS, NINE, FIVE, 0, FIVE)     # 17:00 → değil
    assert schedule_active(WEEKDAYS, NINE, FIVE, 0, FIVE - 1)     # 16:59 → aktif


def test_before_window():
    assert not schedule_active(WEEKDAYS, NINE, FIVE, 0, 8 * 60)   # 08:00


def test_wrong_day():
    assert not schedule_active(WEEKDAYS, NINE, FIVE, 5, 12 * 60)  # Cmt
    assert not schedule_active(WEEKDAYS, NINE, FIVE, 6, 12 * 60)  # Paz


def test_overnight_window():
    # 22:00–06:00 (gece yarısını aşar)
    assert schedule_active({0}, 22 * 60, 6 * 60, 0, 23 * 60)      # 23:00 → aktif
    assert schedule_active({0}, 22 * 60, 6 * 60, 0, 1 * 60)       # 01:00 → aktif
    assert not schedule_active({0}, 22 * 60, 6 * 60, 0, 12 * 60)  # 12:00 → değil


def test_empty_days_never_active():
    assert not schedule_active(frozenset(), NINE, FIVE, 0, 12 * 60)


def test_all_day_all_week():
    for wd in range(7):
        assert schedule_active(set(range(7)), 0, 1439, wd, 12 * 60)
