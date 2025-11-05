# 🕵️ Network Packet Sniffer (Python)

This project is a simple and advanced **Network Packet Sniffer** built in Python using the **Scapy** library.  
It can capture live network traffic and show detailed information about packets just like Wireshark.

---

## ✅ Features

### ✅ Simple Sniffer
- Captures network packets in real-time  
- Shows **Source IP → Destination IP + Protocol**
- Beginner-friendly and easy to understand

### ✅ Advanced Sniffer
- Displays detailed packet information:
  - IP addresses
  - TCP / UDP / ICMP protocols
  - Source and destination ports
  - Packet size & TTL
  - TCP flags (SYN, ACK, FIN, PSH, etc.)
  - Raw payload in HEX + ASCII
- Works similar to Wireshark in terminal

---

## ✅ Requirements

| Requirement | Description |
|------------|-------------|
| Python 3.x | Works in Windows & Linux |
| **Scapy**  | Packet capture & parsing |
| **Npcap (Windows)** | Required for sniffing |

### Install Scapy:
```bash
pip install scapy
