#!/usr/bin/env python3

"""
Network Vulnerability Scanner (Basic Version)

This version adds service identification and banner grabbing.
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


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Attempt to retrieve service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        banner = ""
        try:
            data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()
        except Exception:
            pass

        sock.close()
        return banner
    except Exception:
        return ""


def port_label(port: int) -> str:
    """Resolve service name from port number."""
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


def main():
    parser = argparse.ArgumentParser(description="Basic TCP Port Scanner")
    parser.add_argument("target", help="Target IPv4 address (e.g., 192.168.1.10)")
    parser.add_argument("--timeout", type=float, default=0.6)
    parser.add_argument("--threads", type=int, default=60)
    args = parser.parse_args()

    ip = args.target.strip()

    print(f"\nTarget: {ip}")
    print(f"Scanning {len(COMMON_PORTS)} ports...\n")

    def scan_one(port: int):
        if tcp_connect_scan(ip, port, args.timeout):
            return {
                "port": port,
                "service": port_label(port),
                "banner": grab_banner(ip, port, args.timeout)
            }
        return None

    open_results = []

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
        futures = [executor.submit(scan_one, port) for port in COMMON_PORTS]

        for future in as_completed(futures):
            result = future.result()
            if result:
                open_results.append(result)
                print(f"[OPEN ] {result['port']}/tcp ({result['service']})")

                if result["banner"]:
                    print(f"        banner : {result['banner']}")

    open_results.sort(key=lambda x: x["port"])

    print("\nScan complete.")

    if not open_results:
        print("No open ports found.")


if __name__ == "__main__":
    main()
