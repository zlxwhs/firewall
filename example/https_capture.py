from scapy.all import load_layer, sniff
from scapy.layers.tls.handshake import TLSClientHello

load_layer("tls")

def extract_sni(packet):
    if packet.haslayer(TLSClientHello):
        client_hello = packet[TLSClientHello]
        for ext in getattr(client_hello, "ext", []):
            if hasattr(ext, "servernames"):
                for servername in ext.servernames:
                    print("SNI 도메인 : ", servername.servername.decode())

sniff(filter = "tcp port 443", prn = extract_sni)