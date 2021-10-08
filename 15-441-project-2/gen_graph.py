#!/bin/python3
from scapy.all import *
import matplotlib.pyplot as plt

#Change this to be your pcap file
#You can capture a pcap file with wireshark or tcpdump
#https://support.rackspace.com/how-to/capturing-packets-with-tcpdump/
FILE_TO_READ = 'capture.pcap'

packets = rdpcap(FILE_TO_READ)
packet_list = []
times = []
base = 0
server_port = 15441
num_packets = 0

# This script assumes that only client is sending data to server

for packet in packets:
	payload = packet[Raw].load

    # Count the number of data packets going into the network
	if IP in packet and packet[IP].dport == server_port and 15441 == int.from_bytes(payload[:4], byteorder='big'):
		hlen = int.from_bytes(payload[16:18], byteorder='big')
		plen = int.from_bytes(payload[18:20], byteorder='big')
		if plen > hlen: # Data packet
			num_packets = num_packets + 1
		time = packet.time
		if base == 0:
			base = time
		packet_list.append(num_packets)
		times.append(time - base)

	# Counter the number of ACKs from server to client
	elif IP in packet and packet[IP].sport == server_port and 15441 == int.from_bytes(payload[:4], byteorder='big'):
		mask = int.from_bytes(payload[20:21], byteorder='big')
		if (mask & 4) == 4: # ACK PACKET
			num_packets = max(num_packets - 1, 0)
		time = packet.time
		if base == 0:
			base = time
		packet_list.append(num_packets)
		times.append(time - base)

#https://matplotlib.org/users/pyplot_tutorial.html for how to format and make a good quality graph.
print(packet_list)
plt.scatter(times, packet_list)
plt.savefig("graph.pdf")
