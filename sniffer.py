import scapy.all as scapy

# Function to capture packets
def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(scapy.IP):
        # Extract relevant details
        src_ip = packet[scapy.IP].src
        dest_ip = packet[scapy.IP].dst
        packet_length = len(packet)

        # Check for HTTP traffic (port 80) and alert that the traffic is unencrypted
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 80:
            print(f"[ALERT] Unencrypted HTTP traffic detected: {src_ip} → {dest_ip} | Length: {packet_length} bytes")
            print(f"Protocol: TCP | Destination Port: 80")

        # Detecting ARP Spoofing
        if packet.haslayer(scapy.ARP):
            print(f"[ARP Spoofing Check] ARP Packet: {packet.summary()}")

        # Check for DNS traffic (port 53)
        if packet.haslayer(scapy.UDP) and packet[scapy.UDP].dport == 53:
            print(f"\n[DNS Packet] Source: {src_ip} → Destination: {dest_ip} | Length: {packet_length} bytes")
            print(f"Protocol: UDP | Destination Port: 53")


# Start sniffing the network
scapy.sniff(prn=packet_callback, store=0) # prn=callback function to handle each packet, store=0 to prevent saving packets in memory