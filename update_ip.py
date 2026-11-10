import re
import urllib.request
import os

urls = [
    "https://raw.githubusercontent.com/C24Be/AS_Network_List/refs/heads/main/blacklists/blacklist-v4.txt",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://cinsscore.com/list/ci-badguys.txt",
    "https://check.torproject.org/torbulkexitlist",
    "https://lists.blocklist.de/lists/all.txt",
    "https://www.dshield.org/block.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://blocklist.greensnow.co/greensnow.txt",
    "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt",
    "https://binarydefense.com/banlist.txt"
]

ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b')
ips = set()

for url in urls:
    print(f"Fetching {url}...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8', errors='ignore')
            found = ip_pattern.findall(content)
            print(f"  Found {len(found)} entries.")
            ips.update(found)
    except Exception as e:
        print(f"  Error fetching {url}: {e}")

clean_ips = sorted(ips)

# Вырезаем служебные подсети, которые ломают фаервол
blacklist_exclusions = {"0.0.0.0/8", "0.0.0.0/32", "127.0.0.0/8"}
clean_ips = [ip for ip in clean_ips if ip not in blacklist_exclusions]
print(f"Total unique IPs/CIDRs: {len(clean_ips)}")

os.makedirs("public", exist_ok=True)
with open("public/ips.txt", "w") as f:
    f.write("\n".join(clean_ips) + "\n")
