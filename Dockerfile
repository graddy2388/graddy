FROM python:3.11-slim

WORKDIR /app

# Install package
COPY pyproject.toml .
COPY src/ src/
COPY config/ config/

RUN pip install --no-cache-dir .

# Persistent data directories (override with volumes in production)
RUN mkdir -p data logs reports

EXPOSE 8080

ENV PYTHONUNBUFFERED=1

CMD ["network-bot", "--host", "0.0.0.0", "--port", "8080"]
