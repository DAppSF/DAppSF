FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Prepare upload dir
RUN mkdir -p /data/uploads

EXPOSE 8000
# Gunicorn with 1 worker is fine for MVP; bump later if needed
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:8000", "app:app"]
