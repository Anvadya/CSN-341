from scapy.all import rdpcap

def count_packets_up_to_128_bytes(pcap_file):
    packets = rdpcap(pcap_file)
    count = 0
    for packet in packets:
        if len(packet) <= 128:
            count += 1
    return count

if __name__ == "__main__":
    pcap_file = "ex.pcap"  # Replace with the path to your PCAP file
    num_packets = count_packets_up_to_128_bytes(pcap_file)
    print(f"Number of packets up to 128 bytes: {num_packets}")
