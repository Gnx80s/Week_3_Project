# Python Network Packet Sniffer

A lightweight network packet sniffer built with **Python** and **Scapy**.

This tool captures live IP packets, extracts metadata such as source, destination, protocol, and port details, and saves results into a structured **JSON** file for analysis.

---

## Features

- Capture live IP traffic in real time
- Displays:
  - Source and destination IP addresses
  - Protocol number and name (TCP / UDP / ICMP)
  - Source and destination ports
  - Application service names (HTTP, HTTPS, SSH, etc.)
  - Packet size and timestamps
- Custom port‑to‑service mapping for better readability
- IP-level filter for focused captures
- Clean, readable live terminal output
- Asks the user how many packets to capture.
- Asks for a time delay between each displayed/logged packet.
- Stops gracefully with **Ctrl + C**
- Automatically saves to:packet_log_YYYYMMDD_HHMMSS.json

---

## Requirements

- **Python 3.8 or higher**
- **macOS or Linux** (recommended for raw socket access)
- **Root / Administrator privileges** (needed for packet capture)
- **VS Code** or any Python IDE (optional)

### Install Dependencies

```bash
pip install -r requirements.txt
```
