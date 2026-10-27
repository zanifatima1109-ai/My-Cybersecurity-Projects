from scapy.all import sniff, ARP
from datetime import datetime

arp_table = {}


def detect_arp_change(packet):
    if ARP not in packet:
        return

    if packet[ARP].op != 2:
        return

    ip_address = packet[ARP].psrc
    mac_address = packet[ARP].hwsrc.lower()

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if ip_address not in arp_table:
        arp_table[ip_address] = mac_address

        print(
            f"[INFO] {current_time} | "
            f"IP: {ip_address} | MAC: {mac_address}"
        )

    elif arp_table[ip_address] != mac_address:
        old_mac = arp_table[ip_address]

        print("\n[ALERT] Possible ARP spoofing!")
        print(f"Time: {current_time}")
        print(f"IP address: {ip_address}")
        print(f"Previous MAC: {old_mac}")
        print(f"New MAC: {mac_address}")
        print("Please verify this change.")

        arp_table[ip_address] = mac_address


print("================================")
print(" ARP Detection System Started")
print(" Monitoring ARP packets...")
print(" Press Ctrl+C to stop")
print("================================")

try:
    sniff(
        filter="arp",
        prn=detect_arp_change,
        store=False
    )

except PermissionError:
    print("Permission denied. Try running with sudo.")

except KeyboardInterrupt:
    print("\nMonitoring stopped.")
