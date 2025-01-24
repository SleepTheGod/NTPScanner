from scapy.all import *
import threading
import queue
import requests
import argparse
import random

# Disable Scapy warnings
conf.verb = 0

# Queue for targets
target_queue = queue.Queue()

# Load proxy list
def load_proxies(proxy_url):
    print("[*] Fetching proxy list...")
    try:
        response = requests.get(proxy_url)
        response.raise_for_status()
        proxies = response.text.strip().split('\n')
        print(f"[*] Loaded {len(proxies)} proxies.")
        return proxies
    except Exception as e:
        print(f"[!] Failed to load proxies: {e}")
        return []

# Worker function for scanning
def ntp_worker(proxies):
    while not target_queue.empty():
        target = target_queue.get()
        try:
            # Randomly pick a proxy
            proxy = random.choice(proxies) if proxies else None
            if proxy:
                proxy_host, proxy_port = proxy.split(":")
                conf.proxies = {'udp': (proxy_host, int(proxy_port))}

            # NTP Monlist payload
            ntp_payload = b'\x17\x00\x03\x2a' + b'\x00' * 4
            response = sr1(
                IP(dst=target) / UDP(sport=RandShort(), dport=123) / Raw(load=ntp_payload),
                timeout=1,
                verbose=0
            )

            if response and response.haslayer(Raw):
                print(f"[+] {target} is vulnerable to NTP amplification!")
            else:
                print(f"[-] {target} is not vulnerable.")
        except Exception as e:
            print(f"[!] Error scanning {target}: {e}")
        finally:
            target_queue.task_done()

# Main function
def main(target_file, proxy_url, threads):
    # Load targets
    with open(target_file, "r") as f:
        targets = [line.strip() for line in f if line.strip()]
    for target in targets:
        target_queue.put(target)
    
    # Load proxies
    proxies = load_proxies(proxy_url)

    # Start threads
    print("[*] Starting scan...")
    for _ in range(threads):
        t = threading.Thread(target=ntp_worker, args=(proxies,))
        t.daemon = True
        t.start()

    target_queue.join()
    print("[*] Scan completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="High-Speed NTP Amplification Scanner")
    parser.add_argument("-f", "--file", help="File containing target IPs", required=True)
    parser.add_argument("-p", "--proxy", help="URL to fetch proxy list", required=True)
    parser.add_argument("-t", "--threads", help="Number of threads", type=int, default=10)
    args = parser.parse_args()

    main(args.file, args.proxy, args.threads)
