# Use Ubuntu as base image for better compatibility with security tools
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Update system and install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    dnsutils \
    whois \
    curl \
    wget \
    git \
    network-manager \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install exploitdb from GitHub since it's not in default repos
RUN git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb && \
    ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && \
    chmod +x /opt/exploitdb/searchsploit

# Update searchsploit database
RUN /opt/exploitdb/searchsploit -u || true

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY *.py ./
COPY README.md ./

# Create directories for output and wordlists
RUN mkdir -p /app/output /app/wordlists

# Set permissions
RUN chmod +x *.py

# Create a non-root user for security
RUN useradd -m -u 1000 toolx && \
    chown -R toolx:toolx /app
USER toolx

# Default command - show help
CMD ["python3", "-c", "print('Tool-X Security Assessment Toolkit\\n'); print('Available tools:'); print('- tool_x.py: Port vulnerability scanner'); print('- recon_module.py: Reconnaissance module'); print('- vulnerability_scanner.py: Web vulnerability scanner'); print('- wp_bruteforce.py: WordPress brute forcer'); print('- linux_wifi_extractor.py: WiFi extractor'); print('\\nExample: python3 tool_x.py <host> <start_port> <end_port>')"]