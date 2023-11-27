import numpy as np



import os

import dpkt
import csv
import argparse

parser = argparse.ArgumentParser(description="Command Line String Arguments")

parser.add_argument('string1', type=str, help='Enter name of pcap file')
parser.add_argument('string2', type=str, help='Enter name of csv file')

args = parser.parse_args()

if args.string1 and args.string2:
    pass
else:
    parser.error("Please provide two string arguments.")
input_pcap_file = args.string1 +'.pcap'
output_csv_file = args.string2 + '.csv'
ip_protocol_map = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
}
with open(input_pcap_file, 'rb') as pcap_file, open(output_csv_file, 'w', newline='') as csv_file:
    pcap = dpkt.pcap.Reader(pcap_file)
    csv_writer = csv.writer(csv_file)

    csv_writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol', 'TTL', 'ICMP Type','Flags', 'DNS Query ID', 'Data', 'Data Length','Min TLL','Max TTL','UPTO_128','UPTO_256','UPTO_1024','Shortest_Flow_Pkt','Longest_Flow_Pkt'])
    ip_pairs = {}
    for timestamp, packet in pcap:
      try:
        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        data = ip.data.data
        icmp_type = ''
        dns_query_id = ''
        flags = ''
        if isinstance(ip.data, dpkt.icmp.ICMP):
            print("yes")
            icmp = ip.data
            icmp_type = icmp.type
            data = icmp.data

        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            data = udp.data
            try:
                dns_query_id = int.from_bytes(data[:2], byteorder='big')
            except ValueError:
                dns_query_id = 'N/A'  

        src_ip = dpkt.utils.inet_to_str(ip.src)
        dst_ip = dpkt.utils.inet_to_str(ip.dst)
        protocol = ip.p
        protocol = ip_protocol_map.get(ip.p, 'Unknown')
        ttl = ip.ttl
        if protocol == 'UDP':
          src_port = udp.sport
          dst_port = udp.dport
        elif protocol=='TCP' :
          src_port = ip.data.sport
          dst_port = ip.data.dport
          tcp = ip.data
          flags = f"Urg:{bool(tcp.flags & dpkt.tcp.TH_URG)}, Ack:{bool(tcp.flags & dpkt.tcp.TH_ACK)}, Psh:{bool(tcp.flags & dpkt.tcp.TH_PUSH)}, Rst:{bool(tcp.flags & dpkt.tcp.TH_RST)}, Syn:{bool(tcp.flags & dpkt.tcp.TH_SYN)}, Fin:{bool(tcp.flags & dpkt.tcp.TH_FIN)}"
        else :
          src_port =  ''
          dst_port = ''
        if data is not None:
            data = data.hex()
            data_length = len(data) // 2  
        else:
            data = ''
            data_length = 0
        source_ip = src_ip
        destination_ip = dst_ip
        pkt_length = data_length

        key = (source_ip, destination_ip)

        if key not in ip_pairs:
            ip_pairs[key] = {
                    'minttl': ttl,
                    'maxttl': ttl,
                    'num_pkts_up_to_128_bytes': 0,
                    'num_pkts_128_to_256_bytes': 0,
                    'num_pkts_512_to_1024_bytes': 0,
                    'shortest_flow_pkt': float('inf'),
                    'longest_flow_pkt': 0
            }

        ip_pairs[key]['minttl'] = min(ip_pairs[key]['minttl'], ttl)
        ip_pairs[key]['maxttl'] = max(ip_pairs[key]['maxttl'], ttl)

        if pkt_length <= 128:
                ip_pairs[key]['num_pkts_up_to_128_bytes'] += 1
        elif 128 < pkt_length <= 256:
                ip_pairs[key]['num_pkts_128_to_256_bytes'] += 1
        elif 512 <= pkt_length <= 1024:
                ip_pairs[key]['num_pkts_512_to_1024_bytes'] += 1

        ip_pairs[key]['shortest_flow_pkt'] = min(ip_pairs[key]['shortest_flow_pkt'], pkt_length)
        ip_pairs[key]['longest_flow_pkt'] = max(ip_pairs[key]['longest_flow_pkt'], pkt_length)
        csv_writer.writerow([timestamp, src_ip, dst_ip, src_port, dst_port, protocol, ttl, icmp_type, flags, dns_query_id, data, data_length,ip_pairs[key]['minttl'],ip_pairs[key]['maxttl'],ip_pairs[key]['num_pkts_up_to_128_bytes'],ip_pairs[key]['num_pkts_128_to_256_bytes'],ip_pairs[key]['num_pkts_512_to_1024_bytes'],ip_pairs[key]['shortest_flow_pkt'],ip_pairs[key]['longest_flow_pkt']])
      except:
        pass


