from scapy.all import sniff
from scapy.layers.l2 import ARP
from datetime import datetime

arp_table = {}

log_file = "arp_log.txt"

print("=" * 50)
print(" ARP SPOOFING DETECTOR ")
print("=" * 50)

def detect_arp_spoof(packet):

    if packet.haslayer(ARP):

        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        message = f"IP Address: {ip} --> MAC Address: {mac}"

        print(message)

        with open(log_file, "a") as log:

            log.write(f"{datetime.now()} - {message}\n")

            if ip in arp_table:

                if arp_table[ip] != mac:

                    warning = f"WARNING: Possible ARP Spoofing Detected for IP {ip}"

                    print("\n" + warning + "\n")

                    log.write(f"{datetime.now()} - {warning}\n")

            else:

                arp_table[ip] = mac

print("\nMonitoring Network ARP Packets...\n")

sniff(filter="arp", prn=detect_arp_spoof, store=False, count=20)

print("\nARP Monitoring Completed")