# Python Port Scanner

A lightweight and customizable port scanner written in Python.

## Features

- **TCP Connect Scan**: Performs a full TCP three-way handshake.
- **SYN Scan**: Performs a stealthy half-open scan.
- **ACK Scan**: Used to map out firewall rulesets.
- **Banner Grabbing**: Automatically attempts to grab service banners on open ports.

## Usage

```bash
python main.py --ip <IP_ADDRESS> --port <PORT_OR_RANGE> [OPTIONS]
```

### Arguments

- `--ip`: Target IP address to scan (Required).
- `--port`: Port or port range to scan (e.g., `80` or `80-443`) (Required).
- `--TCS`: Perform a TCP Connect Scan.
- `--SYN`: Perform a SYN Scan (Requires root/administrator privileges).
- `--ACK`: Perform an ACK Scan.

If no scan type is specified, a SYN scan and banner grabbing will be performed by default.

### Examples

Scan a single port using a SYN scan:
```bash
python main.py --ip 192.168.1.1 --port 80 --SYN
```

Scan a range of ports using a TCP Connect scan:
```bash
python main.py --ip 192.168.1.1 --port 20-100 --TCS
```

## Roadmap / In Progress

- [ ] UDP scan
- [ ] FIN / NULL / XMAS scans
- [ ] Protocol-specific service enumeration
