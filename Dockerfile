FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    INTUNEGUARD_HOST=0.0.0.0 \
    INTUNEGUARD_PORT=8095 \
    INTUNEGUARD_MODE=synthetic \
    INTUNEGUARD_DATA_DIR=/data

RUN useradd --create-home --uid 10001 intuneguard \
    && mkdir -p /app /data \
    && chown -R intuneguard:intuneguard /app /data

WORKDIR /app
COPY --chown=intuneguard:intuneguard app.py mcp_server.py ./
COPY --chown=intuneguard:intuneguard backend ./backend
COPY --chown=intuneguard:intuneguard web ./web
COPY --chown=intuneguard:intuneguard docs ./docs

USER intuneguard
EXPOSE 8095

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8095/api/health', timeout=3)"

CMD ["python", "app.py"]
