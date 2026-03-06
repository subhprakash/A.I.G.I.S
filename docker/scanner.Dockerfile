FROM python:3.11

RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    binwalk \
    radare2 \
    yara \
    build-essential

RUN pip install bandit semgrep

WORKDIR /scan

CMD ["bash"]