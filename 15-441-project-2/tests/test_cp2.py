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
PCAP = 'tests/test.pcap'
IFNAME = 'enp0s8'

# which host are we running this pytest script on, server or client?
# if we are running pytest on the server VM, we want
# the testing host to be the client VM and visa-versa
HOSTNAME=subprocess.check_output('hostname').strip()
if HOSTNAME.decode("utf-8")  == 'client':
    TESTING_HOSTNAME = 'server'
    HOSTNAME = 'client'
elif HOSTNAME.decode("utf-8")  == 'server':
    TESTING_HOSTNAME = 'client'
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
HOST_PORT = 15441
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
You will need to add to these tests as you add functionality to your
implementation. It is also important to understand what the given tests
are testing for!
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

payloads = ['pa', 'pytest 1234567']
def test_sequence_number():
    print("Running test_basic_ack_packets()")
    """Basic test: Check if when you data packets,
    the server responds with correct ack packet with correct ack num.
    """
    print("Running test_sequence_number()")
    for payload in payloads:
        print("Testing payload size " + str(len(payload)))
        with Connection(host=TESTING_HOST_IP, user='vagrant',
                        connect_kwargs={'password':'vagrant'}) as conn:
            #try:
                #conn.run(START_TESTING_SERVER_CMD)
                #conn.run('tmux has-session -t pytest_server')
                syn_pkt = eth/ip/udp/CMUTCP(plen=25, seq_num=1000, flags=SYN_MASK)
                #Send and receive packets at layer 2 and return only the first answer
                #syn_pkt.show()
                syn_ack_pkt = srp1(syn_pkt, timeout=TIMEOUT, iface=IFNAME)
                #syn_ack_pkt.show()
                
                if (syn_ack_pkt is None or 
                    syn_ack_pkt[CMUTCP].flags != SYN_MASK|ACK_MASK or 
                    syn_ack_pkt[CMUTCP].ack_num != 1000+1):
                    print("Listener (server) did not properly respond to SYN packet.")
                    print("Test Failed")
                    #conn.run(STOP_TESTING_SERVER_CMD)
                    return
                
                print(syn_ack_pkt[CMUTCP].seq_num)
                
                ack_pkt = eth/ip/udp/CMUTCP(plen=25, seq_num=1001, ack_num=syn_ack_pkt[CMUTCP].seq_num + 1, flags=ACK_MASK)
                #TODO: change server code and verify the effect. 
                empty_pkt = srp1(ack_pkt, timeout=0.5, iface=IFNAME)

                if empty_pkt is not None:
                    print("Listener (server) should not respond to ack pkt.")
                    print("Test Failed")
                    #conn.run(STOP_TESTING_SERVER_CMD)
                    return

                data_pkt = eth/ip/udp/CMUTCP(plen=25 + len(payload), 
                                             seq_num=1001, 
                                             ack_num=syn_ack_pkt[CMUTCP].seq_num + 1, 
                                             flags=0)/Raw(load=payload)
                
                server_ack_pkt = srp1(data_pkt, timeout=TIMEOUT, iface=IFNAME)

                if (server_ack_pkt is None or 
                    server_ack_pkt[CMUTCP].flags != ACK_MASK or 
                    server_ack_pkt[CMUTCP].ack_num != 1001 + len(payload)):
                    print("plen is ", len(payload))
                    print("Listener (server) did not properly respond to data packet.")
                    print("Test Failed")
                    #conn.run(STOP_TESTING_SERVER_CMD)
                    return
                
                fin_pkt = eth/ip/udp/CMUTCP(plen=25, seq_num=1000, flags=FIN_MASK)
                server_fin_ack_pkt = srp1(fin_pkt, timeout=TIMEOUT, iface=IFNAME) 

                print("===========")
                server_fin_ack_pkt.show()

                if (server_fin_ack_pkt is None or server_fin_ack_pkt[CMUTCP].flags != ACK_MASK):
                    print("Listener (server) did not properly respond to fin packet.")
                    print("Test Failed")
                    #conn.run(STOP_TESTING_SERVER_CMD)
                    return

            #finally:
            #    pass
            #    try:
            #        conn.run(STOP_TESTING_SERVER_CMD)
            #    except Exception as e:
            #        pass # Ignore error here that may occur if server is already shut down
            #print("Test Passed")
    

if __name__=='__main__':
    test_sequence_number()