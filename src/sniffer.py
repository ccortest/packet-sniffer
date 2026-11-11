"""
Packet Sniffer - Network Traffic Analysis & IDS Engine.

Captures raw network traffic, parses layers, triggers alerts,
logs activity to a timestamped file, and saves a .pcap capture.
"""

import sys
import os
import logging
from datetime import datetime
from scapy.all import sniff, wrpcap
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# Define base directories
BASE_LOG_DIR = "logs"
CAPTURE_DIR = "captures"
os.makedirs(CAPTURE_DIR, exist_ok=True)

# Create a unique timestamped session folder inside 'logs/' for clean organization
session_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
SESSION_LOG_DIR = os.path.join(BASE_LOG_DIR, f"session_{session_timestamp}")
os.makedirs(SESSION_LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(SESSION_LOG_DIR, "sniffer.log")
PCAP_FILE = os.path.join(CAPTURE_DIR, f"traffic_{session_timestamp}.pcap")

# Configure logging system for this session
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Define ports considered suspicious for our IDS rule engine
SUSPICIOUS_PORTS = {23, 21, 4444, 6667}  # Telnet, FTP, Metasploit default, IRC


def check_suspicious_patterns(src_ip: str, dst_ip: str, dport: int, proto: str) -> None:
    """Evaluates packet attributes against security rules, alerts, and logs events."""
    if dport in SUSPICIOUS_PORTS:
        alert_msg = f"ALERT: Suspicious traffic! Port {dport} ({proto}) targeted from {src_ip} to {dst_ip}"
        print(f"{Fore.RED}[!] {alert_msg}{Style.RESET_ALL}")
        logging.warning(alert_msg)


def packet_callback(packet: Packet) -> None:
    """Callback function executed for every captured packet."""
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        proto = "OTHER"
        dport = 0
        port_info = ""

        if packet.haslayer(TCP):
            proto = "TCP"
            tcp_layer = packet.getlayer(TCP)
            dport = tcp_layer.dport
            port_info = f" | Port: {tcp_layer.sport} -> {dport}"
        elif packet.haslayer(UDP):
            proto = "UDP"
            udp_layer = packet.getlayer(UDP)
            dport = udp_layer.dport
            port_info = f" | Port: {udp_layer.sport} -> {dport}"

        print(f"{Fore.CYAN}[+] [{proto}] {src_ip} ---> {dst_ip}{port_info}{Style.RESET_ALL}")
        logging.info(f"[{proto}] {src_ip} -> {dst_ip}{port_info}")

        if dport:
            check_suspicious_patterns(src_ip, dst_ip, dport, proto)


def main() -> None:
    """Main execution entry point."""
    print(f"{Fore.GREEN}[*] Starting Packet Sniffer & IDS Engine...{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Session logs saving to: '{LOG_FILE}'{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] PCAP capture will save to: '{PCAP_FILE}' upon exit.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Press Ctrl+C to stop and export data.\n{Style.RESET_ALL}")

    logging.info("Packet Sniffer started.")

    try:
        # We capture packets and store them directly in memory via 'store=True'
        # so we can export them to .pcap seamlessly when stopping.
        captured_packets = sniff(filter="ip", prn=packet_callback, store=True)

        # If sniff finishes normally (e.g., if count was set)
        if captured_packets:
            wrpcap(PCAP_FILE, captured_packets)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping packet capture and exporting .pcap...{Style.RESET_ALL}")

        # Access the underlying list from the packet list object returned by sniff
        if 'captured_packets' in locals() and captured_packets:
            wrpcap(PCAP_FILE, captured_packets)
            print(f"{Fore.GREEN}[+] Capture successfully saved to {PCAP_FILE}{Style.RESET_ALL}")

        logging.info("Packet Sniffer stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()