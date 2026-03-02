# wifiaudit — Professional WiFi Reconnaissance Framework

```
██╗    ██╗██╗███████╗██╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
██║    ██║██║██╔════╝██║██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
██║ █╗ ██║██║█████╗  ██║███████║██║   ██║██║  ██║██║   ██║   
██║███╗██║██║██╔══╝  ██║██╔══██║██║   ██║██║  ██║██║   ██║   
╚███╔███╔╝██║██║     ██║██║  ██║╚██████╔╝██████╔╝██║   ██║   
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   
```

A professional-grade WiFi audit framework written in Go, designed for
security audit teams. Built for use **only on networks you are authorized to test**.

---

## Features

- **Monitor Mode Management** — Enable/disable monitor mode, channel hopping (2.4GHz + 5GHz)
- **Passive Network Scanning** — Discover APs with SSID, BSSID, channel, encryption, vendor
- **Client Scanning** — Map connected devices to their APs
- **Handshake Capture** — WPA/WPA2 4-way handshake capture to PCAP
- **Deauthentication** — Send 802.11 deauth frames (authorized use only)
- **MAC List Management** — whitelist / blacklist / known / targets with OUI vendor lookup
- **Session System** — Save, load, export, and merge audit sessions (JSON)
- **Report Generation** — JSON, HTML, and TXT audit reports
- **Interactive TUI** — Full-screen terminal dashboard with live scanning

---

## Requirements

- Linux (kernel 3.2+)
- Go 1.21+
- libpcap-dev (`apt install libpcap-dev`)
- Wireless adapter supporting monitor mode
- Root privileges

### Optional but recommended:
- `airmon-ng` (from aircrack-ng suite) for best monitor mode compatibility
- `iw` package

---

## Installation

```bash
# Install dependencies
sudo apt install libpcap-dev aircrack-ng

# Build
make deps build

# Create data directories
make dirs

# Install system-wide
make install
```

---

## Directory Structure

```
wifiaudit/
├── main.go
├── cmd/                    # CLI command handlers
│   ├── root.go
│   ├── monitor.go
│   ├── scan.go
│   ├── capture.go
│   ├── mac.go
│   ├── report.go
│   ├── session.go
│   └── tui.go
├── internal/
│   ├── monitor/            # Monitor mode management
│   ├── scanner/            # Packet capture & parsing
│   ├── capture/            # Handshake & deauth
│   ├── macs/               # MAC list management
│   ├── reports/            # Report generation
│   ├── session/            # Session persistence
│   └── tui/                # Terminal UI
└── data/
    ├── macs/
    │   ├── whitelist.json  # Authorized devices
    │   ├── blacklist.json  # Known malicious/rogue
    │   ├── known.json      # Identified devices
    │   └── targets.json    # Audit targets
    ├── sessions/           # Saved audit sessions
    ├── reports/            # Generated reports
    └── captures/           # PCAP handshake files
```

---

## Usage

### Interactive TUI Dashboard
```bash
sudo wifiaudit tui -i wlan0
```

### Monitor Mode
```bash
sudo wifiaudit monitor start -i wlan0
sudo wifiaudit monitor status -i wlan0
sudo wifiaudit monitor hop --interval 500
sudo wifiaudit monitor stop -i wlan0
```

### Network Scanning
```bash
# Scan all channels for 60 seconds
sudo wifiaudit scan networks -i wlan0 --duration 60 --output data/sessions/scan1.json

# Scan specific channels
sudo wifiaudit scan networks --channels 1,6,11 --duration 30

# Find clients on a specific AP
sudo wifiaudit scan clients --bssid AA:BB:CC:DD:EE:FF --channel 6
```

### Handshake Capture
```bash
# Passive capture (wait for natural reconnect)
sudo wifiaudit capture handshake --bssid AA:BB:CC:DD:EE:FF --channel 6

# Active capture (send deauth to force reconnect — authorized only)
sudo wifiaudit capture handshake --bssid AA:BB:CC:DD:EE:FF --channel 6 \
  --ssid "TargetNetwork" --deauth --deauth-count 5
```

### MAC Management
```bash
# Add to whitelist
wifiaudit mac add --type whitelist --mac AA:BB:CC:DD:EE:FF --label "Main Router"

# Import a file of known MACs
wifiaudit mac import --type known --file known_devices.csv

# Lookup a MAC
wifiaudit mac lookup --mac AA:BB:CC:DD:EE:FF

# List all blacklisted MACs
wifiaudit mac list --type blacklist
```

### Sessions
```bash
# List saved sessions
wifiaudit session list

# Merge multiple auditor sessions
wifiaudit session merge \
  --files data/sessions/auditor1.json,data/sessions/auditor2.json \
  --output data/sessions/merged.json
```

### Reports
```bash
# Quick summary
wifiaudit report summary --session data/sessions/scan1.json

# Generate HTML report
wifiaudit report generate --session data/sessions/scan1.json \
  --format html --auditor "Jane Smith" --org "ACME Corp"

# Generate JSON report
wifiaudit report generate --session data/sessions/scan1.json --format json
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security audits only**.
Unauthorized use against networks you don't own or have explicit written
permission to test is illegal in most jurisdictions.

The authors assume no liability for misuse of this software.
