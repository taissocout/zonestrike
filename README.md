# ⚡ ZoneStrike — Network Recon & Port Scanner

A lightweight network reconnaissance and port scanning tool built in Python, developed as part of the DIO Cybersecurity Bootcamp.

## Features

- Fast multi-threaded port scanning
- Common ports database with service identification
- Banner grabbing
- HTML report generation with severity classification
- JSON output support
- Configurable port ranges, threads, and timeouts

## Usage
```bash
# Scan common ports
python zonestrike.py 192.168.1.1

# Scan port range
python zonestrike.py scanme.nmap.org --ports 1-1024

# Scan specific ports
python zonestrike.py 10.0.0.1 --ports 80,443,8080,3306

# Generate HTML report
python zonestrike.py 192.168.1.1 --output report.html

# JSON output
python zonestrike.py 192.168.1.1 --json
```

## Options

| Flag | Description |
|------|-------------|
| `--ports` | `common`, `1-1024`, or `80,443,8080` |
| `--threads` | Number of concurrent threads (default: 100) |
| `--timeout` | Connection timeout in seconds (default: 1.0) |
| `--output` | Save HTML report to file |
| `--json` | Output results as JSON |

## Stack

- Python 3.10+
- Standard library only (no external dependencies)

## Security Notice

This tool is for **educational and authorized testing only**.
Never scan systems without explicit written permission.

## License

MIT — DIO Cybersecurity Bootcamp Project
