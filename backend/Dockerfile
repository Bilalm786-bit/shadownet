FROM python:3.12-slim

WORKDIR /app

# System deps for weasyprint and other native packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev libpango-1.0-0 libpangocairo-1.0-0 \
    libcairo2 libgdk-pixbuf-2.0-0 nmap && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    python -m spacy download en_core_web_sm || true

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
