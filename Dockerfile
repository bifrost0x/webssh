FROM python:3.11-slim

LABEL org.opencontainers.image.source=https://github.com/bifrost0x/webssh
LABEL org.opencontainers.image.description="Web SSH Terminal - A modern web-based SSH client with SFTP file manager"
LABEL org.opencontainers.image.licenses=MIT

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=5000 \
    DATA_DIR=/app/data

WORKDIR /app

RUN adduser --disabled-password --gecos "" appuser

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

RUN chown -R appuser:appuser /app && \
    mkdir -p /app/data/logs /app/data/keys && \
    chown -R appuser:appuser /app/data && \
    chmod 700 /app/data && \
    chmod 700 /app/data/logs && \
    chmod 700 /app/data/keys

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os, socket; s=socket.create_connection(('127.0.0.1', int(os.getenv('PORT','5000'))), 2); s.close()"

CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "start:app"]
