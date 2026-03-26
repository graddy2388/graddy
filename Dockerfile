FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (cached layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir \
    "requests>=2.31" \
    "pyyaml>=6.0" \
    "dnspython>=2.4" \
    "schedule>=1.2" \
    "rich>=13.0" \
    "jinja2>=3.1" \
    "cryptography>=41.0" \
    "fastapi>=0.104" \
    "uvicorn[standard]>=0.24" \
    "python-multipart>=0.0.6" \
    "aiofiles>=23.0"

# Install the package (registers the network-bot entry point)
COPY src/ src/
COPY config/ config/
RUN pip install --no-cache-dir --no-deps .

RUN mkdir -p data logs reports

EXPOSE 8080
ENV PYTHONUNBUFFERED=1
ENV NETWORK_BOT_ROOT=/app

CMD ["network-bot"]
