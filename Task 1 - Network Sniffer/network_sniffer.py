import socket
import struct

# Get local IP
HOST = socket.gethostbyname(socket.gethostname())

# Create Raw Socket
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.bind((HOST, 0))

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

print("=" * 70)
print("              BASIC NETWORK SNIFFER")
print("=" * 70)
print("Listening on:", HOST)
print("Press CTRL + C to stop\n")

packet_number = 1

try:
    while True:

        raw_data, addr = sniffer.recvfrom(65535)

        # First 20 bytes = IPv4 Header
        ip_header = raw_data[0:20]

        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 15) * 4

        ttl = iph[5]
        protocol = iph[6]

        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])

        # Protocol Name
        if protocol == 1:
            proto_name = "ICMP"
        elif protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        else:
            proto_name = f"OTHER ({protocol})"

        print("=" * 70)
        print(f"Packet Number : {packet_number}")
        print("-" * 70)
        print(f"Version       : IPv{version}")
        print(f"Header Length : {ihl} Bytes")
        print(f"TTL           : {ttl}")
        print(f"Protocol      : {proto_name}")
        print(f"Source IP     : {src_ip}")
        print(f"Destination IP: {dest_ip}")
        print(f"Packet Length : {len(raw_data)} Bytes")
        print("=" * 70)

        packet_number += 1

except KeyboardInterrupt:
    print("\nStopping Sniffer...")

    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    print("Sniffer Stopped Successfully.")