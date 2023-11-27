from scapy.all import *
import dpkt
import socket
import argparse

def is_private_ip(ip_str):
    # Check if an IP address is a private IP
    ip = ip_str.split('.')
    if len(ip) != 4:
        return False

    first_octet = int(ip[0])
    if (first_octet == 10) or \
       (first_octet == 192 and int(ip[1]) == 168) or \
       (first_octet == 172 and 16 <= int(ip[1]) <= 31):
        return True
    return False

def ip_mac_counts(input_pcap, good_pcap, attack_pcap, threshold):
    packets = rdpcap(input_pcap)

    good_packets = []
    attack_packets = []

    # Dictionary to track packet counts per source IP
    src_ip_count = {}

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            if src_ip in src_ip_count:
                src_ip_count[src_ip] += 1
            else:
                src_ip_count[src_ip] = 1

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            if src_ip_count[src_ip] >= threshold:
                attack_packets.append(packet)
            else:
                good_packets.append(packet)

    wrpcap(good_pcap, good_packets)
    wrpcap(attack_pcap, attack_packets)

 # Timing Filter, Was increasing the overall latency
def filter_malicious_packets(input_pcap, output_good_pcap, output_malicious_pcap, time_window_seconds=60, unique_ip_threshold=10):
    packets = rdpcap(input_pcap)
    good_packets = []
    malicious_packets = []

    # Dictionary to track unique source IPs within the time window
    ip_counts = defaultdict(int)
    time_window_start = datetime.min

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            timestamp = packet.time  # Use the timestamp directly

            # Check if the timestamp is within the current time window
            if (timestamp - time_window_start).total_seconds() > time_window_seconds:
                # Start a new time window
                ip_counts.clear()
                time_window_start = timestamp

            # Update the count for the source IP
            ip_counts[src_ip] += 1

            # Check if the source IP count exceeds the threshold
            if ip_counts[src_ip] > unique_ip_threshold:
                malicious_packets.append(packet)
            else:
                good_packets.append(packet)

    wrpcap(output_good_pcap, good_packets)
    wrpcap(output_malicious_pcap, malicious_packets)


def filter_by_public_private_ip(input_pcap, good_pcap, attack_pcap):
    good_packets = []
    attack_packets = []

    with open(input_pcap, 'rb') as file:
        pcap = dpkt.pcap.Reader(file)
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                    ip = eth.data
                    src_ip = socket.inet_ntoa(ip.src)
                    if not is_private_ip(src_ip):
                        good_packets.append(buf)
                    else:
                        attack_packets.append(buf)
            except dpkt.dpkt.NeedData:
                pass

    with open(good_pcap, 'wb') as good_file:
        pcap_writer = dpkt.pcap.Writer(good_file)
        for packet in good_packets:
            pcap_writer.writepkt(packet)

    with open(attack_pcap, 'wb') as attack_file:
        pcap_writer = dpkt.pcap.Writer(attack_file)
        for packet in attack_packets:
            pcap_writer.writepkt(packet)


def filter_by_size(input_1, output_good_pcap, output_malicious_pcap, size_threshold_low=64, size_threshold_high=1500):
    packets = rdpcap(input_1)
    good_packets = []
    malicious_packets = []

    for packet in packets:
        # Example: Check if packet size is within the specified range
        packet_size = len(packet)
        if size_threshold_low <= packet_size <= size_threshold_high:
            good_packets.append(packet)
        else:
            malicious_packets.append(packet)

    wrpcap(output_good_pcap, good_packets)
    wrpcap(output_malicious_pcap, malicious_packets)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Command Line String Arguments")


    parser.add_argument('str1', type=str, help='Enter name of input file')
    parser.add_argument('str2', type=str, help='Enter name of output file')


    args = parser.parse_args()


    if args.str1 and args.str2:
        pass
    else:
        parser.error("Please provide two string arguments.")
    input_1 = args.str1 +'.pcap'
    output_good_pcap = "Final_Non_Malacious.pcap"
    output_malicious_pcap = "Final_Malacious.pcap"

    filter_by_size(input_1, output_good_pcap, output_malicious_pcap)
    input_pcap = "Final_Non_Malacious.pcap"
    good_pcap = args.str2 +'NON-Malacious.pcap'
    attack_pcap = args.str2 +'Malacious.pcap'
    filter_by_public_private_ip(input_pcap, good_pcap, attack_pcap)
    #filter_malicious_packets(input_pcap, output_good_pcap, output_malicious_pcap)

