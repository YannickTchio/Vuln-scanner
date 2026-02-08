**Network Vulnerability Scanner (Python)**

A lightweight network vulnerability scanner built in Python for educational and defensive security purposes.
The tool performs TCP connect port scanning, best-effort banner grabbing, and produces structured security reports in both text and JSON formats.

**Ethical Use Notice**
**This project is intended only for systems you own or have explicit authorization to test.**

**Features**
	- TCP Connect Port Scanning:	Scan common service ports or a custom port list
	- Multi-Threaded Execution: Concurrent scanning using ThreadPoolExecutor
	- Banner Grabbing:	Attempts to collect service banners when available
	- Risk Context Mapping:	Security-relevant risk notes for common exposed services
	- Automated Reporting:	Human-readable text report and Machine-readable JSON output
	- Minimal Dependencies:	Built using Python standard libraries only

**Project Motivation**
This project was developed to explore defensive network security fundamentals, including:
- Service exposure analysis
-	Secure infrastructure assessment
-	Ethical reconnaissance workflows
-	Security documentation and reporting
It mirrors early-stage tasks commonly performed in SOC, GRC, and security engineering roles.

**Technologies Used**
-	Python 3
-	socket – low-level network communication
-	concurrent.futures – multi-threaded scanning
-	argparse – command-line interface design
-	json – structured output for automation
Tested on Linux / Kali Linux.

**Project Structure**
vuln-scanner/
├── src/
│   └── scanner.py        # Main scanner logic
├── reports/              # Generated scan reports
│   ├── report_<target>.txt
│   └── report_<target>.json
├── README.md
├── LICENSE
└── .gitignore

**Usage**
Basic Scan (Common Ports)
python3 src/scanner.py 127.0.0.1

**Scan Specific Ports**
python3 src/scanner.py 127.0.0.1 --ports 22,80,443,8080

**Generate Reports**
python3 src/scanner.py 127.0.0.1 --report --json
Reports are saved in the reports/ directory.

**Advanced Example**
python3 src/scanner.py 192.168.1.10 \
  --ports 22,80,443 \
  --threads 40 \
  --timeout 0.5 \
  --report \
  --json

**Sample Output**
[OPEN ] 8080/tcp (http-alt)
       note: HTTP-alt open (admin panels often exposed).

**Sample JSON Output**
{
  "target": "127.0.0.1",
  "generated": "2026-02-07T19:14:34",
  "open_ports": [
    {
      "port": 8080,
      "service": "http-alt",
      "banner": "",
      "risk": "HTTP-alt open (admin panels often exposed)."
    }
  ]
}

**Ethical & Security Considerations**
This scanner intentionally avoids:
-	Exploitation techniques
-	Credential attacks
-	Brute-force methods
-	CVE weaponization
Its goal is visibility, assessment, and documentation, aligned with responsible security practices.

**Learning Outcomes**
Through this project, I strengthened my understanding of:
-	Network service exposure
-	TCP/IP security fundamentals
-	Ethical vulnerability assessment
-	Risk documentation and reporting
-	Python-based security tooling

**Future Enhancements**
Planned improvements include:
-	Service fingerprinting
-	CVE correlation
-	Risk scoring models
-	SIEM-friendly output formats
-	Scan profiling and rate limiting

**License**
This project is licensed under the MIT License.
See the LICENSE file for details.

**Author**
**Yannick Tchio**
**Computer Engineering — Cybersecurity Concentration**
**University of Arkansas**



