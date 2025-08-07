from scapy.all import rdpcap, ARP, DNS, IP
from collections import Counter, defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import os

# === CONFIG ===
PCAP_FILE = r"C:\Users\Arun prakash\Downloads\vpn\arp8.pcapng"
OUTPUT_DIR = "./network_report"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# === READ PACKETS ===
packets = rdpcap(PCAP_FILE)

arp_requests = []
arp_responses = []
arp_sources = Counter()
arp_targets = Counter()
arp_who_has_counter = Counter()
arp_is_at_counter = Counter()

ip_mac_map = defaultdict(set)
mac_ip_map = defaultdict(set)

dns_query_counter = Counter()
dns_response_counter = Counter()
dns_errors = []

# === ANALYZE PACKETS ===
for pkt in packets:
    if ARP in pkt:
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        src_mac = pkt[ARP].hwsrc

        ip_mac_map[src_ip].add(src_mac)
        mac_ip_map[src_mac].add(src_ip)

        arp_sources[src_ip] += 1
        arp_targets[dst_ip] += 1

        if pkt[ARP].op == 1:
            arp_requests.append(pkt)
            arp_who_has_counter[dst_ip] += 1
        elif pkt[ARP].op == 2:
            arp_responses.append(pkt)
            arp_is_at_counter[src_ip] += 1

    if DNS in pkt:
        if pkt[DNS].qr == 0:
            query = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else "unknown"
            dns_query_counter[query] += 1
        elif pkt[DNS].qr == 1:
            if pkt[DNS].ancount == 0:
                src_ip = pkt[IP].src if IP in pkt else "unknown"
                dns_errors.append((src_ip, pkt.summary()))
            dns_response_counter[pkt[DNS].id] += 1

# === CONFLICT DETECTION ===
ip_conflicts = {ip: list(macs) for ip, macs in ip_mac_map.items() if len(macs) > 1}
mac_conflicts = {mac: list(ips) for mac, ips in mac_ip_map.items() if len(ips) > 1}

# === EXCEL EXPORT ===
excel_path = os.path.join(OUTPUT_DIR, "network_report.xlsx")
with pd.ExcelWriter(excel_path, engine='xlsxwriter') as writer:
    # ARP data
    pd.DataFrame(arp_sources.most_common(), columns=["IP", "ARP Packets"]).to_excel(writer, sheet_name="ARP_Senders", index=False)
    pd.DataFrame(arp_who_has_counter.most_common(), columns=["Target IP", "Requests"]).to_excel(writer, sheet_name="ARP_Targets", index=False)
    pd.DataFrame(arp_is_at_counter.most_common(), columns=["Sender IP", "Responses"]).to_excel(writer, sheet_name="ARP_Replies", index=False)

    # DNS data
    pd.DataFrame(dns_errors, columns=["Source IP", "Error Summary"]).to_excel(writer, sheet_name="DNS_Errors", index=False)
    pd.DataFrame(dns_query_counter.most_common(), columns=["Domain", "Query Count"]).to_excel(writer, sheet_name="Top_DNS_Queries", index=False)

    # Conflicts
    pd.DataFrame([(ip, macs) for ip, macs in ip_conflicts.items()], columns=["IP", "MACs"]).to_excel(writer, sheet_name="IP_Conflicts", index=False)
    pd.DataFrame([(mac, ips) for mac, ips in mac_conflicts.items()], columns=["MAC", "IPs"]).to_excel(writer, sheet_name="MAC_Conflicts", index=False)

print(f"\n[✓] Excel report saved at: {excel_path}")

# === OPTIONAL: VISUALIZATION ===
plt.figure(figsize=(14, 8))

plt.subplot(2, 2, 1)
top_arp = arp_sources.most_common(5)
labels, values = zip(*top_arp) if top_arp else ([], [])
plt.bar(labels, values, color="orange")
plt.title("Top ARP Senders")
plt.xticks(rotation=45)
plt.ylabel("Packets")

plt.subplot(2, 2, 2)
top_targets = arp_who_has_counter.most_common(5)
labels, values = zip(*top_targets) if top_targets else ([], [])
plt.bar(labels, values, color="blue")
plt.title("Top ARP Request Targets")
plt.xticks(rotation=45)
plt.ylabel("Requests")

plt.subplot(2, 2, 3)
top_responders = arp_is_at_counter.most_common(5)
labels, values = zip(*top_responders) if top_responders else ([], [])
plt.bar(labels, values, color="green")
plt.title("Top ARP Reply Senders")
plt.xticks(rotation=45)
plt.ylabel("Responses")

plt.subplot(2, 2, 4)
top_dns = dns_query_counter.most_common(5)
labels, values = zip(*top_dns) if top_dns else ([], [])
plt.bar(labels, values, color="purple")
plt.title("Top DNS Queries")
plt.xticks(rotation=45)
plt.ylabel("Count")

plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/network_arp_dns_summary.png")
plt.show()

print(f"[+] Chart saved as: {OUTPUT_DIR}/network_arp_dns_summary.png")
