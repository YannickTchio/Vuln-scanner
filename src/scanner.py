#!/usr/bin/env python3

"""
Network Vulnerability Scanner (Basic Version)

This is the initial version of the scanner. 
It performs a basic TCP connect scan on common ports.

"""

import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports to scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5900, 8080
]


def tcp_connect_scan(ip: str, port: int, timeout: float) -> bool:
    """Attempt to connect to a TCP port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="Basic TCP Port Scanner")
    parser.add_argument("target", help="Target IPv4 address (e.g., 192.168.1.10)")
    parser.add_argument("--timeout", type=float, default=0.6, help="Socket timeout (default: 0.6)")
    parser.add_argument("--threads", type=int, default=60, help="Number of threads (default: 60)")
    args = parser.parse_args()

    ip = args.target.strip()

    print(f"\nTarget: {ip}")
    print(f"Scanning {len(COMMON_PORTS)} ports...\n")

    open_ports = []

    # Multithreaded scanning
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
        futures = {executor.submit(tcp_connect_scan, ip, port, args.timeout): port for port in COMMON_PORTS}

        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
                print(f"[OPEN ] {port}/tcp")

    open_ports.sort()

    print("\nScan complete.")

    if not open_ports:
        print("No open ports found.")
    else:
        print(f"Open ports: {open_ports}")


if __name__ == "__main__":
    main()

