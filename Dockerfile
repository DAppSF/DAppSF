FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update \
 && apt-get install -y --no-install-recommends binutils file \
 && rm -rf /var/lib/apt/lists/*

COPY . .
RUN mkdir -p /data/uploads
# PYTHONPATH not strictly needed now, but harmless
ENV PYTHONPATH=/app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
# NOTE: module path changes because we're *inside* the package dir now
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:8000", "wsgi:app"]
