from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
import binascii

conf.use_pcap = True

def advanced_show(packet):
    print("\n================ PACKET CAPTURED ================")

    # Ethernet & IP info
    if IP in packet:
        ip = packet[IP]
        print(f"Source IP:\t{ip.src}")
        print(f"Destination IP:\t{ip.dst}")
        print(f"TTL:\t\t{ip.ttl}")
        print(f"Packet Length:\t{len(packet)} bytes")

    # TCP
    if TCP in packet:
        tcp = packet[TCP]
        print("Protocol:\tTCP")
        print(f"Source Port:\t{tcp.sport}")
        print(f"Dest Port:\t{tcp.dport}")
        print(f"Flags:\t\t{tcp.flags}")

    # UDP
    elif UDP in packet:
        udp = packet[UDP]
        print("Protocol:\tUDP")
        print(f"Source Port:\t{udp.sport}")
        print(f"Dest Port:\t{udp.dport}")

    # ICMP
    elif ICMP in packet:
        icmp = packet[ICMP]
        print("Protocol:\tICMP")
        print(f"ICMP Type:\t{icmp.type}")
        print(f"ICMP Code:\t{icmp.code}")

    # Raw Payload
    if Raw in packet:
        payload = packet[Raw].load
        hex_payload = binascii.hexlify(payload).decode()
        print(f"Payload (HEX):\n{hex_payload}")

        # ASCII printable text
        try:
            ascii_payload = payload.decode('utf-8', errors='ignore')
            print(f"Payload (ASCII):\n{ascii_payload}")
        except:
            print("Payload cannot be displayed as text.")

print("Advanced Sniffer Started... Press CTRL+C to stop.")
sniff(store=False, prn=advanced_show)
