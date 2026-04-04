#!/usr/bin/env python3

"""
Network Vulnerability Scanner (Basic Version)

This version adds service identification, banner grabbing,
and risk annotations for common exposed services.
"""

import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports to scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5900, 8080
]

RISK_HINTS = {
    21:  "FTP open — plaintext transfer; check anonymous login.",
    22:  "SSH open — ensure strong auth and restrict access.",
    23:  "TELNET open — HIGH RISK: unencrypted channel.",
    25:  "SMTP open — check open relay; enforce TLS.",
    53:  "DNS open — check recursion and zone transfer restrictions.",
    80:  "HTTP open — review headers, auth, and OWASP risks.",
    110: "POP3 open — prefer TLS; disable plaintext.",
    139: "NetBIOS open — legacy exposure; restrict if possible.",
    143: "IMAP open — prefer TLS; disable plaintext.",
    443: "HTTPS open — verify TLS configuration and certificate validity.",
    445: "SMB open — lateral movement risk; check version and signing.",
    3306:"MySQL open — restrict to trusted hosts; enforce strong credentials.",
    3389:"RDP open — restrict exposure; enforce MFA and lockout.",
    8080:"HTTP-alt open — admin panels often exposed on this port.",
}


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
                "banner": grab_banner(ip, port, args.timeout),
                "risk": RISK_HINTS.get(port, "")
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

                if result["risk"]:
                    print(f"        note   : {result['risk']}")

    open_results.sort(key=lambda x: x["port"])

    print("\nScan complete.")

    if not open_results:
        print("No open ports found.")


if __name__ == "__main__":
    main()
