import os
import sys

# Proje kökünü import yoluna ekle ki testler `servers`, `cache_loop`, `settings`
# gibi modülleri import edebilsin (bu dosya kökte durduğu için).
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
