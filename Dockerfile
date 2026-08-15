FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Resolver tarafı ---
COPY app.py run_all.py ./
# Resolver + panel'in paylaştığı leaf modüller (log şifreleme + DoH HTTP/2 istemcisi).
COPY logcrypto.py doh_client.py ./
COPY servers ./servers
COPY db_ops ./db_ops
COPY project_control ./project_control
COPY logs ./logs
# --- Web sitesi (Django projesi) ---
COPY dns_resolver ./dns_resolver
RUN touch .env

# Django statik dosyalarını topla (whitenoise runtime'da servis eder).
RUN python dns_resolver/manage.py collectstatic --noinput

# Non-root kullanıcı + Django'nun SQLite'ı (auth/session/admin) için yazılabilir dizin.
RUN useradd --no-create-home --uid 1000 --shell /usr/sbin/nologin resolver \
 && mkdir -p /app/data && chown resolver:resolver /app/data
USER resolver

ENV BIND_ADDRESS=0.0.0.0 \
    UDP_PORT=5300 \
    DJANGO_DEBUG=False \
    DJANGO_DB_PATH=/app/data/db.sqlite3 \
    SITE_BIND=0.0.0.0 \
    SITE_PORT=8000

# interval 15m: healthcheck sorgusu (example.com) DB'ye loglandigi icin
# sik aralik tabloyu gurultuye boguyordu (30s = gunde 2880 satir).
HEALTHCHECK --interval=15m --timeout=6s --start-period=10s --retries=3 \
    CMD python -m project_control.healthcheck || exit 1

# Tek container, iki ayrı process (resolver + web sitesi) -> run_all.py yönetir.
CMD ["python", "run_all.py"]
