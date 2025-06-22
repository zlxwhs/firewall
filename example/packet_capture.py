from scapy.all import *

def packet_callbhack(packet):
    print(f"캡처된 패킷 : {packet.summary()}")

sniff(prn=packet_callbhack)