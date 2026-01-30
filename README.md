# ProcShark

**Network Traffic Analyzer with Process Correlation**

ProcShark is a lightweight network capture tool for Windows that correlates network traffic with processes in real-time. It provides visibility into which applications are communicating over the network, what protocols they're using, and detailed packet-level information.

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **Process Correlation**: Identifies which process owns each network connection
- **Real-time Capture**: Live packet capture with minimal latency
- **Protocol Analysis**: Automatic detection of HTTP, DNS, TLS, QUIC, and 30+ services
- **Rich Terminal UI**: Colored output with protocol highlighting
- **Flexible Filtering**: Filter by process path, protocol, or direction
- **Export Support**: Save captures to JSON or CSV for offline analysis
- **Live Statistics**: Real-time bandwidth, packet rates, and top talkers

## Requirements

- **Windows 10/11** (uses WinDivert for packet capture)
- **Python 3.9+**
- **Administrator privileges** (required for packet capture)

## Installation

### From Source

```bash
git clone https://github.com/yourusername/procshark.git
cd procshark
pip install -r requirements.txt
```

## Usage

### Basic Capture

Capture all network traffic (requires Administrator):

```bash
python procshark.py
```

### Filter by Process

Capture traffic only from a specific executable:

```bash
python procshark.py -f "C:\Program Files\Mozilla Firefox\firefox.exe"
```

Or capture traffic from all executables in a directory:

```bash
python procshark.py -f "C:\Program Files\Mozilla Firefox\"
```

### Filter by Protocol

Capture only HTTP and DNS traffic:

```bash
python procshark.py -p http,dns
```

Exclude specific protocols:

```bash
python procshark.py --exclude-protocol quic
```

### Export to File

Export captured packets to JSON:

```bash
python procshark.py --export capture.json
```

Export to CSV for spreadsheet analysis:

```bash
python procshark.py --export capture.csv
```

### Live Statistics

Show real-time statistics panel:

```bash
python procshark.py --stats
```

### Compact Output

Use single-line compact format:

```bash
python procshark.py --compact
```

### Hide Payload

Capture without displaying payload data:

```bash
python procshark.py --no-payload
```

### Full Options

```
python procshark.py [OPTIONS]

Capture Options:
  -f, --filter PATH       Filter by executable or directory path
  -p, --protocol PROTO    Filter by protocol (tcp,udp,http,dns,tls,quic,all)
  --exclude-protocol      Exclude specified protocols
  --no-loopback           Hide loopback traffic (127.0.0.1, ::1)

Display Options:
  --no-payload            Don't show packet payload
  --max-payload N         Maximum payload bytes to display (default: 1024)
  --no-color              Disable colored output
  --compact               Use compact single-line output format

Export Options:
  --export FILE           Export captured packets to file (JSON or CSV)
  --export-format FMT     Force export format: json, csv

Statistics Options:
  --stats                 Show live statistics panel
  --stats-interval N      Statistics refresh interval (default: 1.0s)

Other Options:
  --refresh N             PID map refresh interval (default: 0.5s)
  -v, --verbose           Enable verbose output
  -h, --help              Show help message
  --version               Show version number
```

## Output Format

### Standard Output

```
Time         Dir Proto Flags        Source                   Destination              Size   Service  Process              Application
12:34:56.789 OUT TCP   SYN          192.168.1.100:54321      93.184.216.34:443        52     HTTPS    firefox(1234)        TLS handshake (HTTPS)
```

### Payload Display

When payload is shown (default), you'll see hex and ASCII representations:

```
            payload_hex(517B): 1603010200010001fc030...
            payload_ascii(517B): ................
```

## Supported Protocols

### Transport Layer
| Protocol | Detection |
|----------|-----------|
| TCP | Native |
| UDP | Native |

### Application Layer
| Protocol | Detection Method |
|----------|------------------|
| HTTP | Request parsing (method, host, path) |
| HTTPS/TLS | TLS record detection |
| DNS | Query parsing (domain, type) |
| QUIC | UDP/443 with QUIC header |

### Service Identification (by port)
DNS, HTTP, HTTPS, SSH, FTP, SMTP, IMAP, POP3, LDAP, RDP, SMB, MySQL, PostgreSQL, Redis, MongoDB, MQTT, and 20+ more.

## Use Cases

### Security Analysis
- Monitor which processes are making network connections
- Detect unexpected outbound connections
- Analyze application behavior during malware analysis

### Development & Debugging
- Debug network issues in applications
- Verify API calls and responses
- Monitor microservice communication

### Network Forensics
- Capture traffic for incident response
- Export evidence to JSON/CSV
- Correlate traffic with process activity

### Performance Analysis
- Identify bandwidth-heavy processes
- Monitor connection patterns
- Track protocol distribution

## Architecture

```
ProcShark/
├── procshark.py         # Main entry point
├── core/                # Core modules
│   ├── __init__.py      # Package initialization
│   ├── cli.py           # Command-line interface
│   ├── capture.py       # Packet capture (WinDivert)
│   ├── process.py       # Process correlation (psutil)
│   ├── protocols.py     # Protocol analysis
│   ├── display.py       # Rich terminal UI
│   ├── export.py        # JSON/CSV export
│   └── stats.py         # Live statistics
├── tests/               # Unit tests
├── requirements.txt     # Dependencies
└── README.md            # Documentation
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/yourusername/procshark.git
cd procshark
pip install -r requirements-dev.txt
pytest tests/
```

## Acknowledgments

- [WinDivert](https://reqrypt.org/windivert.html) - Windows packet capture library
- [pydivert](https://github.com/ffalcinelli/pydivert) - Python bindings for WinDivert
- [psutil](https://github.com/giampaolo/psutil) - Cross-platform process utilities
- [Rich](https://github.com/Textualize/rich) - Rich text and beautiful formatting

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for legitimate network analysis, debugging, and security research purposes. Users are responsible for ensuring they have appropriate authorization before capturing network traffic. Use responsibly and in compliance with applicable laws and regulations.
