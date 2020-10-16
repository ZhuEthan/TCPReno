from __future__ import print_function

import pytest
import subprocess
from scapy.all import *
import pwd
import os
from fabric import Connection
import time
import socket

CODE_DIR = '/vagrant/15-441-project-2'
PCAP = '/vagrant/15-441-project-2/tests/test.pcap'
IFNAME = 'enp0s8'

# which host are we running this pytest script on, server or client?
# if we are running pytest on the server VM, we want
# the testing host to be the client VM and visa-versa
HOSTNAME=subprocess.check_output('hostname').strip()
if HOSTNAME.decode("utf-8")  == 'client':
    TESTING_HOSTNAME = 'client'
    HOSTNAME = 'client'
elif HOSTNAME.decode("utf-8")  == 'server':
    TESTING_HOSTNAME = 'server'
    HOSTNAME = 'server'
else:
    raise Exception(
        "Unexpected hostname: {}. You must run these tests in the client or server VM.".format(HOSTNAME))

# you might need to update these for the network setting on your VMs
IP_ADDRS = {'client': '10.0.0.2',
            'server': '10.0.0.1'}
MAC_ADDRS = {'client': '08:00:27:a7:fe:b1',
            'server': '08:00:27:22:47:1c'}
HOST_IP = IP_ADDRS[HOSTNAME]
HOST_MAC = MAC_ADDRS[HOSTNAME]
HOST_PORT = 1234
TESTING_HOST_IP = IP_ADDRS[TESTING_HOSTNAME]
TESTING_HOST_MAC = MAC_ADDRS[TESTING_HOSTNAME]
TESTING_HOST_PORT = 15441
# we can use these command to start/stop the testing server in a background process
START_TESTING_SERVER_CMD = 'tmux new -s pytest_server -d /vagrant/15-441-project-2/tests/testing_server'
STOP_TESTING_SERVER_CMD = 'tmux kill-session -t pytest_server'
# default scapy packets headers we'll use to send packets
eth = Ether(src=HOST_MAC, dst=TESTING_HOST_MAC)
ip = IP(src=HOST_IP, dst=TESTING_HOST_IP)
udp = UDP(sport=HOST_PORT, dport=TESTING_HOST_PORT)

FIN_MASK = 0x2
ACK_MASK = 0x4
SYN_MASK = 0x8

TIMEOUT = 3

"""
These tests assume there is only one connection in the PCAP
and expects the PCAP to be collected on the server.
All of the basic tests pass on the starter code, without
you having to make any changes. You will need to change these
tests as you add functionality to your implementation.
"""

# we can make CMUTCP packets using scapy
class CMUTCP(Packet):
    name = "CMU TCP"
    fields_desc=[IntField("identifier",15441),
                 ShortField("source_port",HOST_PORT),
                 ShortField("destination_port",TESTING_HOST_PORT),
                 IntField("seq_num",0),
                 IntField("ack_num",0),
                 ShortField("hlen",25),
                 ShortField("plen",25),
                 ByteEnumField("flags" , 0,
                      { FIN_MASK: "FIN",
                        ACK_MASK: "ACK" ,
                        SYN_MASK: "SYN" ,
                        FIN_MASK | ACK_MASK: "FIN ACK",
                        SYN_MASK | ACK_MASK: "SYN ACK"} ),
                 ShortField("advertised_window",1),
                 ShortField("extension_length",0),
                 StrLenField("extension_data", None,
                            length_from=lambda pkt: pkt.extension_length)]

    def answers(self, other):
        return (isinstance(other, CMUTCP))


bind_layers(UDP, CMUTCP)

def test_pcap_packets_max_size():
    """Basic test: Check packets are smaller than max size"""
    print("Running test_pcap_packets_max_size()")
    print("Please note that it's now testing on a sample test.pcap file. "
          "You should generate your own pcap file and run this test.")
    packets = rdpcap(PCAP)
    if len(packets)<=10:
         print("Test Failed")
         return
    for pkt in packets:
        if CMUTCP in pkt:
            if len(pkt[CMUTCP]) > 1400:
                print("Found packet with length greater than max size")
                print("Test Failed")
                return
    print("Test passed")

def test_pcap_acks():
    """Basic test: Check that every data packet sent has a corresponding ACK
    Ignore handshake packets.
    """
    print("Running test_pcap_acks()")
    print("Please note that it's now testing on a sample test.pcap file. "
          "You should generate your own pcap file and run this test.")
    packets = rdpcap(PCAP)
    if len(packets)<=10:
        print("Test Failed")
        return
    seq_nums = []
    ack_nums = []
    for pkt in packets:
        if CMUTCP in pkt:
            # ignore handshake packets, should test in a different test
            if (pkt[CMUTCP].flags == 0):
                seq_nums.append(pkt[CMUTCP].seq_num)
            elif (pkt[CMUTCP].flags == ACK_MASK):
                ack_nums.append(pkt[CMUTCP].ack_num-1)
    # probably not the best way to do this test!
    if set(seq_nums) == set(ack_nums):
        print("Test Passed")
    else:
        print("Test Failed")

# this will run try to run the server and client code
def test_run_server_client():
    """Basic test: Run server and client, and initiate the file transfer process."""
    print("Running test_run_server_client()")
    start_server_cmd = 'tmux new -s pytest_server -d /vagrant/15-441-project-2/server'
    start_client_cmd = 'tmux new -s pytest_client -d /vagrant/15-441-project-2/client'
    stop_server_cmd = 'tmux kill-session -t pytest_server'
    stop_client_cmd = 'tmux kill-session -t pytest_client'

    failed = False

    with Connection(host=TESTING_HOST_IP, user='vagrant', connect_kwargs={'password':'vagrant'}) as conn:
        try:
            conn.run('pwd')
            conn.run(start_client_cmd)
            conn.run('tmux has-session -t pytest_client')
            conn.local(start_server_cmd)
            conn.local('tmux has-session -t pytest_server')
            # exit when server finished receiving file
            conn.local('while tmux has-session -t pytest_server; do sleep 1; done')
        except:
            failed = True
        finally:
            try:
                conn.run('tmux has-session -t pytest_client')
                conn.run(stop_client_cmd)
            except Exception as e:
                pass # Ignore error here that may occur if client already shut down
            try:
                conn.local('tmux has-session -t pytest_server')
                conn.local(stop_server_cmd)
            except Exception as e:
                pass # Ignore error here that may occur if server already shut down
            if failed:
                print("Test failed")
            else:
                print("Test passed") 

            
def test_basic_reliable_data_transfer():
    """Basic test: Check that when you run server and client starter code
    that the input file equals the output file
    """
    # Can you think of how you can test this? Give it a try!
    pass

def test_basic_retransmit():
    """Basic test: Check that when a packet is lost, it's retransmitted"""
    # Can you think of how you can test this? Give it a try!
    pass

if __name__=='__main__':
     test_pcap_packets_max_size()
     test_pcap_acks()
     test_run_server_client()
