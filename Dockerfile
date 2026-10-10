FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -q -r requirements.txt

RUN DEBIAN_FRONTEND=noninteractive apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends binutils file \
 && rm -rf /var/lib/apt/lists/*

COPY . .
RUN mkdir -p /data/uploads
ENV PYTHONPATH=/app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "-k", "gthread", "-w", "2", "--threads", "4", "-b", "0.0.0.0:8000", "--timeout", "600", "--keep-alive", "65", "--log-level", "warning", "wsgi:app"]
