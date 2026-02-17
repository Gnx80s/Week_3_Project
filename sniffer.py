from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
from datetime import datetime
import time

# List to store packet data
packet_data = []

# Common well-known ports (professional mapping)
COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

# Function to process each packet
def process_packet(packet):
    if packet.haslayer(IP):
        protocol_number = packet[IP].proto
        protocol_name = "Other"
        src_port = "-"
        dst_port = "-"
        service_name = "-"

        if packet.haslayer(TCP):
            protocol_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            service_name = COMMON_PORTS.get(dst_port) or COMMON_PORTS.get(src_port, "Unknown")

        elif packet.haslayer(UDP):
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            service_name = COMMON_PORTS.get(dst_port) or COMMON_PORTS.get(src_port, "Unknown")

        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"

        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": packet[IP].src,
            "destination_ip": packet[IP].dst,
            "protocol_number": protocol_number,
            "protocol_name": protocol_name,
            "source_port": src_port,
            "destination_port": dst_port,
            "service_name": service_name,
            "length": len(packet)
        }

        packet_data.append(data)

        print(f"[+] {data['source_ip']}:{src_port} → "
              f"{data['destination_ip']}:{dst_port} | "
              f"{protocol_number} ({protocol_name}) | "
              f"Service: {service_name} | "
              f"Size:{data['length']}")

        # Introduce a small delay to slow down output
        time.sleep(DELAY_BETWEEN_PACKETS)


# Function to save packets to a JSON file
def save_to_json():
    filename = f"packet_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(packet_data, f, indent=4)
    print(f"\n[*] Saved {len(packet_data)} packets to {filename}")


# ------------------------------------
#   USER INPUT SECTION
# ------------------------------------
try:
    # Ask for number of packets to capture
    num_packets = input("Enter number of packets to capture (press Enter for unlimited): ").strip()
    count = None if num_packets == "" else int(num_packets)

    # Ask for delay between packet logs
    delay_input = input("Enter delay between packet logs in seconds (default 0): ").strip()
    DELAY_BETWEEN_PACKETS = float(delay_input) if delay_input else 0.0

    print(f"\n[*] Starting packet capture... Press Ctrl+C to stop.\n")
    sniff(prn=process_packet, store=False, filter="ip", count=count)

except KeyboardInterrupt:
    print("\n[*] KeyboardInterrupt detected, saving JSON...")
finally:
    save_to_json()
    print("[*] Capture stopped. Exiting...")