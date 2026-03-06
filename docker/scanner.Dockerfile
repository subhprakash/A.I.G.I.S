FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    nmap \
    binwalk \
    yara \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install security tools via pip
RUN pip install bandit semgrep

# Install Nikto manually
RUN git clone https://github.com/sullo/nikto.git /opt/nikto

# Install Radare2 manually
RUN git clone https://github.com/radareorg/radare2.git /opt/radare2 \
    && cd /opt/radare2 \
    && sys/install.sh

WORKDIR /scan

CMD ["bash"]