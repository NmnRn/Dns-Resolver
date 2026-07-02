FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py settings.py cache_loop.py ./
COPY logs ./logs
RUN touch .env

RUN useradd --no-create-home --uid 1000 --shell /usr/sbin/nologin resolver
USER resolver

ENV BIND_ADDRESS=0.0.0.0 \
    UDP_PORT=5300

EXPOSE 5300/udp 5300/tcp

CMD ["python", "app.py"]
