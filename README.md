# NetworkSniffer

**NetworkSniffer** is a simple Python application designed to mopnitor network traffic and print warnings for suspicious traffic in real-time.

## Features

- Real-time packet capturing
- Protocol analysis (e.g., TCP, UDP, ARP)
- Source and destination IP address tracking
- Port number identification  
- ALerts for suspicious behavior (e.g., Port 80 used for unencrypted HTTP traffic, check DNS traffic on port 53 for suspicious behavior)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/luitel-prayush/NetworkSniffer.git
   cd NetworkSniffer

2. **Install dependencies:**

   Ensure you have Python 3 installed. Then, install the required packages:

   ```bash
   pip install scapy

## Usage

1. Run the sniffer script with appropriate permissions(root permissions may be required to capture network packets):

   ```bash
   sudo python sniffer.py

## Example Output

1. When running, the application will display captured packets like this:

   ```yaml
   Packet: Ether / IP / TCP 192.168.1.176:65370 > 34.237.73.95:https A
  
