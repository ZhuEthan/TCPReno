#!/bin/python3
#------------------------------------------------#
#   score_calculator.py                          #
#                                                #
#   Calculates JFI and throughput for multiple   #
#   TCP connections                              #
#                                                #
#   Run the following on the server VM:          #
#   $ ./receiver 441 &                           #
#   $ ./receiver 641 &                           #
#   $ sudo ./score_calculator.py                 #
#                                                #
#   Kartik Chitturi <kchittur@andrew.cmu.edu>    #
#------------------------------------------------#

import os
import sys
import subprocess
import time
from scapy.all import *


FIN_MASK = 0x2
ACK_MASK = 0x4
SYN_MASK = 0x8

DATA_ACK_MASK = ACK_MASK

MAX_ADV_WINDOW = 2**32-1

class CMUTCP(Packet):
    name = "CMU TCP"
    fields_desc=[IntField("identifier",15441),
                 ShortField("source_port", 15441),
                 ShortField("destination_port", 15441),
                 IntField("seq_num",0),
                 IntField("ack_num",0),
                 ShortField("hlen",25),
                 ShortField("plen",25),
                 ByteEnumField("flags" , DATA_ACK_MASK,
                      { FIN_MASK: "FIN",
                        ACK_MASK: "ACK" ,
                        SYN_MASK: "SYN" ,
                        FIN_MASK | ACK_MASK: "FIN ACK",
                        SYN_MASK | ACK_MASK: "SYN ACK"} ),
                 IntField("advertised_window",MAX_ADV_WINDOW),
                 ShortField("extension_length",0),
                 StrLenField("extension_data", None,
                            length_from=lambda pkt: pkt.extension_length)]

    def answers(self, other):
        return isinstance(other, CMUTCP) and not (ICMP in other) and not (ICMP in self)

bind_layers(UDP, CMUTCP)

def get_cmu(pkt):
    if CMUTCP in pkt:
        return pkt[CMUTCP]
    elif Raw in pkt:
        try:
            return CMUTCP(pkt[Raw])
        except:
            return None
    else:
        return None

def silent_call(command):
    return subprocess.call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def silent_check_call(command):
    return subprocess.check_call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_jfi(throughputs):
    numer = sum(throughputs)*sum(throughputs)
    denom = len(throughputs) * sum([x*x for x in throughputs])
    return numer/denom

def main():
    # Check if running as root
    if(os.geteuid() != 0):
        print("Need to run script using sudo")
        return

    # Set network statistics
    bandwidth = 50 # in Mbps
    latency = 50 # in ms
    loss = 0.1 # as a percentage

    silent_call('sudo tcdel enp0s8 --all')
    time.sleep(0.1)
    comm = 'sudo tcset enp0s8 --rate {}Mbps --delay {}ms --loss {}%'.format(bandwidth, latency, loss)
    silent_call(comm)



    start_sender441 = "tmux new -s sender441 -d './sender 441'"
    start_sender641 = "tmux new -s sender641 -d './sender 641'"
    remove_sender441 = 'tmux kill-session -t sender441'
    remove_sender641 = 'tmux kill-session -t sender641'

    try:
        silent_check_call(start_sender441)
        silent_check_call(start_sender641)
    except:
        print("Could not run executables")
        silent_call(remove_sender441)
        silent_call(remove_sender641)
        return

    sniffer = AsyncSniffer(iface='enp0s8')
    sniffer.start()
    print("Run both receivers on server VM")

    while True:
        s = silent_call('tmux has-session -t sender441')
        t = silent_call('tmux has-session -t sender641')
        if s and t:
            break
        time.sleep(1)

    sniffer.stop()


    start_time_441, end_time_441  = float("inf"), -1*float("inf")
    start_time_641, end_time_641 = float("inf"), -1*float("inf")
    pkts = sniffer.results
    for pkt in pkts:
        cpkt = get_cmu(pkt)
        if cpkt is None:
            continue
        if cpkt.source_port == 15441:
            start_time_441 = min(start_time_441, pkt.time)
            end_time_441 = max(end_time_441, pkt.time)
        if cpkt.source_port == 15641:
            start_time_641 = min(start_time_641, pkt.time)
            end_time_641 = max(end_time_641, pkt.time)

    time_completed_441 = end_time_441-start_time_441
    time_completed_641 = end_time_641-start_time_641

    reliable_441 = silent_call('diff 15441_output test_20MB_file')
    reliable_641 = silent_call('diff 15641_output test_20MB_file') 

    if reliable_441 or reliable_641:
        print("Did not transfer files reliably")
    else:
        print("Reliably transfered files")

    tput_441 = 20.0/time_completed_441 * 8
    tput_641 = 20.0/time_completed_641 * 8

    print("441 Throughput: " + str(tput_441) + " Mbps")
    print("641 Throughput: " + str(tput_641) + " Mbps")

    jfi = get_jfi([tput_441, tput_641])
    avg_tput =  (tput_441 + tput_641)/2.

    print("Average Throughput {} Mbps. JFI: {}".format(avg_tput, jfi))
    print("Score: {}".format(jfi*jfi*avg_tput))

if __name__ == "__main__":
    main()
