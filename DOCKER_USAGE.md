# Docker Usage Guide

## Quick Start with Docker

### Build and Run
```bash
# Build the Docker image
docker-compose build

# Run the container interactively
docker-compose run --rm tool-x bash

# Or run a specific tool directly
docker-compose run --rm tool-x python3 tool_x.py 192.168.1.1 1 1000
```

### Available Commands

#### Port Vulnerability Scanner
```bash
docker-compose run --rm tool-x python3 tool_x.py <host> <start_port> <end_port>
```

#### Reconnaissance Module
```bash
docker-compose run --rm tool-x python3 recon_module.py
```

#### Web Vulnerability Scanner
```bash
docker-compose run --rm tool-x python3 vulnerability_scanner.py
```

#### WordPress Brute Force
```bash
docker-compose run --rm tool-x python3 wp_bruteforce.py <target_url> [options]
```

#### WiFi Extractor (requires host network access)
```bash
docker-compose run --rm tool-x python3 linux_wifi_extractor.py
```

### Volume Mounts

The container is configured with the following volume mounts:
- `./output:/app/output` - Scan results and output files
- `./wordlists:/app/wordlists` - Custom wordlists for brute force attacks

### Network Configuration

The container runs with `network_mode: "host"` to enable:
- Network scanning capabilities
- Access to host network interfaces
- Proper nmap functionality

### Security Considerations

- Container runs as non-root user (`toolx`)
- Required capabilities: `NET_ADMIN`, `NET_RAW` for network scanning
- Use only in authorized testing environments