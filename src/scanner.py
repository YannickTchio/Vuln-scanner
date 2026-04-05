#!/usr/bin/env python3

"""
Network Vulnerability Scanner (Basic Version)

This version adds service identification, banner grabbing,
risk annotations, custom port selection, and report generation.
"""

import socket
import argparse
import json
from datetime import datetime
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


def parse_ports(ports_arg: str):
    """Parse comma-separated ports."""
    if not ports_arg.strip():
        return COMMON_PORTS

    ports = []
    for p in ports_arg.split(","):
        p = p.strip()
        if not p:
            continue
        if p.isdigit():
            val = int(p)
            if 1 <= val <= 65535:
                ports.append(val)

    return sorted(set(ports))


def write_text_report(path: str, ip: str, results: list):
    """Write scan results to a text report."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("Vulnerability Scanner Report\n")
        f.write(f"Target: {ip}\n")
        f.write(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n\n")

        if not results:
            f.write("No open ports found on scanned list.\n")
            return

        for r in results:
            f.write(f"Port {r['port']}/tcp ({r['service']}) - OPEN\n")
            if r["banner"]:
                f.write(f"  Banner: {r['banner']}\n")
            if r["risk"]:
                f.write(f"  Risk note: {r['risk']}\n")
            f.write("\n")


def write_json_report(path: str, ip: str, results: list):
    """Write scan results to a JSON report."""
    payload = {
        "target": ip,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "open_ports": results
    }
    with open(path, "w", encoding="utf-8") as jf:
        json.dump(payload, jf, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Basic TCP Port Scanner")
    parser.add_argument("target", help="Target IPv4 address (e.g., 192.168.1.10)")
    parser.add_argument("--ports", default="", help="Comma-separated ports (e.g., 22,80,443)")
    parser.add_argument("--timeout", type=float, default=0.6)
    parser.add_argument("--threads", type=int, default=60)
    parser.add_argument("--report", action="store_true", help="Write a text report into ./reports/")
    parser.add_argument("--json", action="store_true", help="Write a JSON report into ./reports/")
    args = parser.parse_args()

    ip = args.target.strip()
    ports = parse_ports(args.ports)

    print(f"\nTarget: {ip}")
    print(f"Scanning {len(ports)} ports...\n")

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
        futures = [executor.submit(scan_one, port) for port in ports]

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

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.report:
        text_path = f"reports/report_{ip.replace('.', '_')}_{ts}.txt"
        write_text_report(text_path, ip, open_results)
        print(f"\nReport written to: {text_path}")

    if args.json:
        json_path = f"reports/report_{ip.replace('.', '_')}_{ts}.json"
        write_json_report(json_path, ip, open_results)
        print(f"JSON written to: {json_path}")


if __name__ == "__main__":
    main()
