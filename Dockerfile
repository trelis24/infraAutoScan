FROM python:3.12-slim

# --- Apt packages ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    bsdmainutils \
    dnsutils \
    zip \
    unzip \
    nmap \
    ffuf \
    git \
    hydra \
    tmux \
    vim \
    && rm -rf /var/lib/apt/lists/*

# --- Pip packages ---
RUN pip install --no-cache-dir \
    unidecode \
    bs4 \
    requests \
    lxml \
    pyyaml \
    colorama \
    openpyxl \
    pandas

WORKDIR /app


# --- Github wordlists/tools — cloned into the project's own dirs ---
RUN mkdir -p bin \
 && git clone --depth 1 https://github.com/drwetter/testssl.sh bin/testssl \
 && rm -rf bin/testssl/.git

RUN mkdir -p wordlists/seclists \
 && cd wordlists/seclists \
 && git init \
 && git remote add origin https://github.com/danielmiessler/SecLists \
 && git sparse-checkout init --cone \
 && git sparse-checkout set Discovery/Web-Content \
 && git pull --depth 1 origin master \
 && cd Discovery/Web-Content \
 && find . -type f ! -name "raft-*" -delete \
 && cd /app \
 && rm -rf wordlists/seclists/.git

COPY . .

# Make sure output dirs exist even before first run
RUN mkdir -p results scans logs
RUN touch scope.txt

CMD ["python", "infraAutoScan.py"]