# 🛡️ Python Packet Sniffer & IDS Engine

A lightweight, modular network traffic analysis tool and intrusion detection system (IDS) built with Python and Scapy. Designed for real-time packet sniffing, protocol filtering, suspicious traffic pattern alerts, activity logging, and `.pcap` export compatible with Wireshark.

---

## 🚀 Features

- **Real-Time Packet Capture:** Listens to network interfaces using Scapy.
- **Protocol & Layer Parsing:** Automatically inspects and breaks down IP, TCP, and UDP layers, extracting source/destination IPs and ports.
- **IDS Rule Engine:** Triggers real-time console warnings and security logs when suspicious ports (e.g., Telnet, FTP, Metasploit default ports) are targeted.
- **Structured Session Logging:** Automatically organizes logs into timestamped session directories under `logs/`.
- **Wireshark Compatibility:** Exports captured traffic directly into `.pcap` files stored in `captures/` upon exit.
- **Cross-Platform Colored Output:** Utilizes `colorama` for a clear, readable terminal interface.

---

## 📁 Project Structure

```text
packet-sniffer/
│
├── captures/            # Stores exported .pcap traffic capture files
├── logs/                # Session-based timestamped execution logs
├── src/                 # Source code
│   ├── __init__.py
│   └── sniffer.py       # Main script
│
├── .gitignore           # Ignored system & cache files
├── requirements.txt     # Project dependencies
└── README.md            # Project documentation
```

---

## 🛠️ Installation & Prerequisites

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/packet-sniffer.git](https://github.com/YOUR_USERNAME/packet-sniffer.git)
   cd packet-sniffer
   ```
2. **Install Npcap (Windows Users):**
   - Download and install [Npcap](https://nmap.org/npcap/).
   - Ensure you check **"Support WinPcap API-compatible mode"** during installation.
3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Usage

> **Note:** Packet capture requires raw socket privileges. Run your terminal as **Administrator** (Windows) or using **sudo** (Linux/macOS).

Run the sniffer script from the project root:
```bash
python src/sniffer.py
```

- Press **`Ctrl + C`** at any time to gracefully stop the capture, export the `.pcap` file, and exit.

---

## 🔍 Validation

Captured traffic `.pcap` files can be opened and analyzed directly in **Wireshark** for deep protocol inspection and cross-validation.