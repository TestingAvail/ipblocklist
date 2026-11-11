import asyncio
import aiohttp
import ssl
import ipaddress
import os

URLS = [
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

# Запрещенные для блокировки сети (локальные, приватные, служебные)
EXCLUSIONS = [
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
]

def is_valid_ip_or_cidr(text):
    """Проверяет, является ли строка валидным IPv4 или CIDR, и не входит ли в исключения."""
    text = text.strip()
    if not text:
        return False
    try:
        # Пытаемся распарсить как сеть (поддерживает и одиночные IP)
        net = ipaddress.ip_network(text, strict=False)
        if net.version != 4:
            return False
        
        # Проверяем на пересечение с исключениями
        for excl in EXCLUSIONS:
            if net.overlaps(excl):
                return False
        return True
    except ValueError:
        return False

async def fetch_url_async(session, url, semaphore):
    ips = set()
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0"
    }
    
    async with semaphore:
        for attempt in range(3):
            try:
                print(f"Fetching {url} (attempt {attempt + 1})...")
                async with session.get(url, headers=headers, timeout=45, ssl=False) as response:
                    if response.status == 200:
                        text = await response.text(errors='ignore')
                        # Ищем все строки, похожие на IP
                        for line in text.splitlines():
                            # Извлекаем потенциальный IP или CIDR из строки (игнорируя комментарии)
                            line = line.split('#')[0].strip()
                            if not line: continue
                            
                            # Разбиваем по пробелам, чтобы найти токен с IP
                            parts = line.split()
                            for part in parts:
                                if is_valid_ip_or_cidr(part):
                                    ips.add(part)
                        
                        print(f"  Found {len(ips)} valid entries.")
                        return ips
            except Exception as e:
                print(f"  Error fetching {url}: {type(e).__name__}")
            
            if attempt < 2:
                await asyncio.sleep(2)
                
    return ips

async def fetch_all_async():
    all_ips = set()
    semaphore = asyncio.Semaphore(10) # Не перегружаем сервера
    
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(ssl=ssl_context, limit=10)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_url_async(session, url, semaphore) for url in URLS]
        results = await asyncio.gather(*tasks)
        
    for ips in results:
        all_ips.update(ips)
        
    return all_ips

def save_ips(ips_set):
    # Сортируем по числовому значению, а не по строке
    clean_ips = sorted(list(ips_set), key=lambda ip: ipaddress.ip_network(ip, strict=False).network_address)
    print(f"Total unique IPs/CIDRs after exclusions: {len(clean_ips)}")

    os.makedirs("public", exist_ok=True)
    with open("public/ips.txt", "w") as f:
        f.write("\n".join(clean_ips) + "\n")
    print("Saved to public/ips.txt")

if __name__ == "__main__":
    print("--- Начинаем сборку IP-блоклиста ---")
    collected_ips = asyncio.run(fetch_all_async())
    save_ips(collected_ips)
