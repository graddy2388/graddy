FROM python:3.11-slim-bookworm

WORKDIR /app

# System packages: nmap + pen-test / recon tools available in Debian repos
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    masscan \
    hydra \
    smbclient \
    ldap-utils \
    dnsutils \
    netcat-openbsd \
    curl \
    git \
    unzip \
    iputils-ping \
    net-tools \
    whois \
    wget \
    perl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# nikto was removed from Debian Bookworm repos; install from GitHub
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    || echo "nikto install skipped"

# sqlmap (install via pip to avoid repo issues)
RUN pip install --no-cache-dir sqlmap || true

# enum4linux (Perl script from upstream)
RUN wget -q https://github.com/CiscoCXSecurity/enum4linux/raw/master/enum4linux.pl \
        -O /usr/local/bin/enum4linux \
    && chmod +x /usr/local/bin/enum4linux \
    || echo "enum4linux install skipped"

# nuclei binary from ProjectDiscovery
ARG TARGETARCH=amd64
RUN set -e; \
    ARCH="${TARGETARCH}"; \
    NUCLEI_VER="3.3.4"; \
    URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${ARCH}.zip"; \
    curl -sL "${URL}" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    || echo "nuclei install skipped (network or arch issue)"

# Python application dependencies
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
    "aiofiles>=23.0" \
    "python-nmap>=0.7.1" \
    "APScheduler>=3.10" \
    "aiohttp>=3.9" \
    "ldap3>=2.9" \
    "reportlab>=4.0" \
    "Pillow>=10.0" \
    "python-crontab>=3.0"

# Install the network-bot package
COPY src/ src/
COPY config/ config/
RUN pip install --no-cache-dir --no-deps .

RUN mkdir -p data logs reports nuclei-templates

EXPOSE 8080
ENV PYTHONUNBUFFERED=1
ENV NETWORK_BOT_ROOT=/app

CMD ["network-bot"]
