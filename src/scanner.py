#!/usr/bin/env python3
"""
Network Vulnerability Scanner (Educational)

Features:
- TCP connect scan (common ports or user-provided list)
- Best-effort banner grabbing
- Threaded scanning for speed
- Text report + JSON report output

Use only on systems you own or have explicit permission to test.
"""

import socket
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5900, 8080
]

RISK_HINTS = {
    21:  "FTP open (consider FTPS/SFTP; check anonymous login).",
    22:  "SSH open (good; ensure strong auth, restrict access).",
    23:  "TELNET open (HIGH RISK: unencrypted).",
    25:  "SMTP open (check open relay, enforce TLS).",
    53:  "DNS open (check recursion, zone transfer restrictions).",
    80:  "HTTP open (review headers, auth, OWASP risks).",
    110: "POP3 open (prefer TLS / disable plaintext).",
    139: "NetBIOS open (legacy exposure; restrict if possible).",
    143: "IMAP open (prefer TLS / disable plaintext).",
    443: "HTTPS open (check TLS config/certs).",
    445: "SMB open (check version/signing; restrict exposure).",
    3389:"RDP open (restrict exposure; MFA; lockout).",
    3306:"MySQL open (restrict to trusted hosts; strong creds).",
    8080:"HTTP-alt open (admin panels often exposed).",
}


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


def parse_ports(ports_arg: str):
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
    payload = {
        "target": ip,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "open_ports": results
    }
    with open(path, "w", encoding="utf-8") as jf:
        json.dump(payload, jf, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Network Vulnerability Scanner (TCP connect scan + banner grab + reports)."
    )
    parser.add_argument("target", help="Target IPv4 address (e.g., 192.168.1.10)")
    parser.add_argument("--ports", default="", help="Comma-separated ports (e.g., 22,80,443). Default: common ports")
    parser.add_argument("--timeout", type=float, default=0.6, help="Socket timeout in seconds (default: 0.6)")
    parser.add_argument("--threads", type=int, default=60, help="Number of threads (default: 60)")
    parser.add_argument("--report", action="store_true", help="Write a text report into ./reports/")
    parser.add_argument("--json", action="store_true", help="Write a JSON report into ./reports/")
    args = parser.parse_args()

    ip = args.target.strip()
    ports = parse_ports(args.ports)

    print(f"\nTarget: {ip}")
    print(f"Scanning {len(ports)} ports (TCP connect scan)...\n")

    def scan_one(p: int):
        if tcp_connect_scan(ip, p, args.timeout):
            service = port_label(p)
            banner = grab_banner(ip, p, args.timeout)
            risk = RISK_HINTS.get(p, "")
            return {"port": p, "service": service, "banner": banner, "risk": risk}
        return None

    open_results = []

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futures = [ex.submit(scan_one, p) for p in ports]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                open_results.append(res)
                print(f"[OPEN ] {res['port']}/tcp ({res['service']})")
                if res["banner"]:
                    print(f"       banner: {res['banner']}")
                if res["risk"]:
                    print(f"       note: {res['risk']}")

    open_results.sort(key=lambda x: x["port"])

    if not open_results:
        print("No open ports found on the scanned list.")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.report:
        text_path = f"reports/report_{ip.replace('.', '_')}_{ts}.txt"
        write_text_report(text_path, ip, open_results)
        print(f"\nReport written to: {text_path}")

    if args.json:
        json_path = f"reports/report_{ip.replace('.', '_')}_{ts}.json"
        write_json_report(json_path, ip, open_results)
        print(f"JSON written to: {json_path}")

    print("")


if __name__ == "__main__":
    main()


