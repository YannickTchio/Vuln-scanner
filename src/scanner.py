#!/usr/bin/env python3
"""
Network Vulnerability Scanner (Educational)

Features:
- Input validation (IPv4 address check)
- TCP connect scan (common ports or user-provided list)
- Port range syntax support (e.g. 22-443)
- Best-effort banner grabbing
- NIST SP 800-53 aligned risk annotations
- Threaded scanning for speed
- Progress bar via tqdm (optional — falls back gracefully)
- Text report + JSON report output
- Auto-creates reports/ directory

Use only on systems you own or have explicit permission to test.
"""

import socket
import argparse
import json
import sys
import os
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5900, 8080
]

# Risk notes aligned to NIST SP 800-53 Rev 5 control families
RISK_HINTS = {
    21:  {"note": "FTP open — plaintext transfer; check anonymous login.",        "nist": "AC-3, IA-2, SC-8"},
    22:  {"note": "SSH open — ensure strong auth and restrict access.",           "nist": "AC-17, IA-5"},
    23:  {"note": "TELNET open — HIGH RISK: unencrypted channel.",                "nist": "AC-17, IA-2, SC-8"},
    25:  {"note": "SMTP open — check open relay; enforce TLS.",                   "nist": "SC-8, SI-8"},
    53:  {"note": "DNS open — check recursion and zone transfer restrictions.",   "nist": "CM-7, SC-5"},
    80:  {"note": "HTTP open — review headers, auth, OWASP Top 10.",             "nist": "SC-8, SI-10"},
    110: {"note": "POP3 open — prefer TLS; disable plaintext.",                  "nist": "SC-8, IA-5"},
    139: {"note": "NetBIOS open — legacy exposure; restrict if possible.",        "nist": "CM-7, SC-5"},
    143: {"note": "IMAP open — prefer TLS; disable plaintext.",                  "nist": "SC-8, IA-5"},
    443: {"note": "HTTPS open — verify TLS config and certificate validity.",     "nist": "SC-8, SC-23"},
    445: {"note": "SMB open — lateral movement risk; check version and signing.", "nist": "CM-7, SC-5, SI-3"},
    3306:{"note": "MySQL open — restrict to trusted hosts; enforce strong creds.","nist": "AC-3, IA-5"},
    3389:{"note": "RDP open — restrict exposure; enforce MFA and lockout.",       "nist": "AC-17, IA-5, AU-2"},
    8080:{"note": "HTTP-alt open — admin panels often exposed on this port.",     "nist": "CM-7, AC-3"},
}


#  Validation 

def validate_ip(ip: str) -> str:
    """Validate and return a clean IPv4 address string, or exit with a clear error."""
    try:
        ipaddress.IPv4Address(ip.strip())
        return ip.strip()
    except ValueError:
        print(f"\n[ERROR] '{ip}' is not a valid IPv4 address.")
        print("        Example: python3 scanner.py 192.168.1.10\n")
        sys.exit(1)


def parse_ports(ports_arg: str):
    """Parse comma-separated ports and ranges (e.g. '22,80,443,8000-8100')."""
    if not ports_arg.strip():
        return COMMON_PORTS

    ports = []
    for token in ports_arg.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            parts = token.split("-", 1)
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                start, end = int(parts[0]), int(parts[1])
                if 1 <= start <= end <= 65535:
                    ports.extend(range(start, end + 1))
                else:
                    print(f"[WARN] Skipping invalid range: {token}")
        elif token.isdigit():
            val = int(token)
            if 1 <= val <= 65535:
                ports.append(val)
            else:
                print(f"[WARN] Skipping out-of-range port: {val}")

    return sorted(set(ports))


#  Scanning

def tcp_connect_scan(ip: str, port: int, timeout: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()


def grab_banner(ip: str, port: int, timeout: float) -> str:
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
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


#  Reporting

def write_text_report(path: str, ip: str, results: list):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("Network Vulnerability Scanner — Assessment Report\n")
        f.write("=" * 60 + "\n")
        f.write(f"Target    : {ip}\n")
        f.write(f"Generated : {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"Open ports: {len(results)}\n\n")

        if not results:
            f.write("No open ports found on scanned list.\n")
            return

        for r in results:
            f.write(f"Port {r['port']}/tcp ({r['service']}) — OPEN\n")
            if r["banner"]:
                f.write(f"  Banner  : {r['banner']}\n")
            if r["risk"]["note"]:
                f.write(f"  Risk    : {r['risk']['note']}\n")
            if r["risk"]["nist"]:
                f.write(f"  NIST    : SP 800-53 — {r['risk']['nist']}\n")
            f.write("\n")


def write_json_report(path: str, ip: str, results: list):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "target": ip,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "open_port_count": len(results),
        "open_ports": results
    }
    with open(path, "w", encoding="utf-8") as jf:
        json.dump(payload, jf, indent=2)


#  Main

def main():
    parser = argparse.ArgumentParser(
        description="Network Vulnerability Scanner — TCP connect scan, banner grab, NIST-aligned reports."
    )
    parser.add_argument("target", help="Target IPv4 address (e.g. 192.168.1.10)")
    parser.add_argument("--ports",   default="",    help="Ports or ranges (e.g. 22,80,443,8000-8080). Default: common ports.")
    parser.add_argument("--timeout", type=float, default=0.6,  help="Socket timeout in seconds (default: 0.6)")
    parser.add_argument("--threads", type=int,   default=60,   help="Number of threads (default: 60)")
    parser.add_argument("--report",  action="store_true", help="Write text report to ./reports/")
    parser.add_argument("--json",    action="store_true", help="Write JSON report to ./reports/")
    args = parser.parse_args()

    ip = validate_ip(args.target)
    ports = parse_ports(args.ports)

    print(f"\nTarget : {ip}")
    print(f"Ports  : {len(ports)} to scan")
    print(f"Threads: {args.threads}  Timeout: {args.timeout}s\n")

    def scan_one(p: int):
        if tcp_connect_scan(ip, p, args.timeout):
            service = port_label(p)
            banner  = grab_banner(ip, p, args.timeout)
            risk    = RISK_HINTS.get(p, {"note": "", "nist": ""})
            return {"port": p, "service": service, "banner": banner, "risk": risk}
        return None

    open_results = []

    if TQDM_AVAILABLE:
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futures = {ex.submit(scan_one, p): p for p in ports}
            with tqdm(total=len(ports), desc="Scanning", unit="port") as pbar:
                for fut in as_completed(futures):
                    res = fut.result()
                    if res:
                        open_results.append(res)
                        tqdm.write(f"[OPEN ] {res['port']}/tcp ({res['service']})")
                        if res["banner"]:
                            tqdm.write(f"        banner : {res['banner']}")
                        if res["risk"]["note"]:
                            tqdm.write(f"        note   : {res['risk']['note']}")
                        if res["risk"]["nist"]:
                            tqdm.write(f"        nist   : {res['risk']['nist']}")
                    pbar.update(1)
    else:
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futures = [ex.submit(scan_one, p) for p in ports]
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    open_results.append(res)
                    print(f"[OPEN ] {res['port']}/tcp ({res['service']})")
                    if res["banner"]:
                        print(f"        banner : {res['banner']}")
                    if res["risk"]["note"]:
                        print(f"        note   : {res['risk']['note']}")
                    if res["risk"]["nist"]:
                        print(f"        nist   : {res['risk']['nist']}")

    open_results.sort(key=lambda x: x["port"])

    print(f"\n{'─'*40}")
    print(f"Scan complete - {len(open_results)} open port(s) found.")

    if not open_results:
        print("No open ports found on the scanned list.")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ip = ip.replace(".", "_")

    if args.report:
        text_path = f"reports/report_{safe_ip}_{ts}.txt"
        write_text_report(text_path, ip, open_results)
        print(f"Report  : {text_path}")

    if args.json:
        json_path = f"reports/report_{safe_ip}_{ts}.json"
        write_json_report(json_path, ip, open_results)
        print(f"JSON    : {json_path}")

    print("")


if __name__ == "__main__":
    main()
