# 🛡️ NetScan Pro — Network Security Scanner & Firewall Visualizer

A professional-grade **network security tool** built with Python and Streamlit that lets you scan hosts for open ports, analyze service risk, and simulate firewall rule chains — all in a dark-themed, interactive web interface.

---

## 📸 Features

| Feature | Description |
|---|---|
| **Port Scanner** | TCP Connect, TCP SYN, UDP, and Comprehensive scans |
| **Service Detection** | Identifies 60+ common services by port number |
| **Vulnerability Hints** | Risk-rated advisories for each discovered open port |
| **Firewall Simulator** | Priority-based ALLOW/DENY rule engine |
| **Packet Tester** | Test any custom packet against your rule chain |
| **Visual Dashboard** | Plotly charts: port status donut, risk map, traffic flow |
| **Scan vs Rules** | Auto-simulates scan results through your active firewall rules |

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/netscan-pro.git
cd netscan-pro
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

> **Optional (for full scan capability):** Install nmap on your system:
> - **Linux**: `sudo apt install nmap`
> - **macOS**: `brew install nmap`
> - **Windows**: Download from [nmap.org](https://nmap.org/download.html)
>
> Without nmap, the tool falls back to a Python TCP Connect scanner automatically.

### 3. Run the App
```bash
streamlit run app.py
```

Open your browser to `http://localhost:8501`

---

## 🗂️ Project Structure

```
netscan-pro/
├── app.py              # Streamlit frontend — all UI tabs and charts
├── scanner.py          # Scanning engine — nmap wrapper + Python fallback
├── firewall.py         # Firewall rule simulator — priority chain logic
├── requirements.txt    # Python dependencies
└── README.md
```

---

## 🔍 Scanner Details

### Scan Types
| Type | Method | Root Required? |
|---|---|---|
| TCP Full Connect | Full 3-way handshake | ❌ No |
| TCP SYN | Half-open / stealth | ✅ Yes |
| UDP | Datagram probe | ✅ Yes (recommended) |
| Comprehensive | SYN + version detection | ✅ Yes |

### Port Presets
- **Common Ports** — 30 most important ports
- **Top 100** — 100 frequently targeted ports
- **Well-Known (1–1024)** — Full privileged port range
- **Custom** — Enter your own range (e.g. `80,443,8080` or `1-500`)

### Vulnerability Rating System
- 🔴 **Critical** — Exposed service with known severe risk (RDP, VNC, Redis, MongoDB)
- ⚠️ **Warning** — Elevated risk requiring review (FTP, MySQL, MSSQL, SMB)
- ✅ **Info** — Best practice notes (HTTPS, SSH hardening)

---

## 🔥 Firewall Simulator

### How Rules Work
Rules are matched **in priority order** (lowest number = highest priority). The first matching rule wins.

```
Priority 1:  DENY  TCP  *  *  port=23    → Block Telnet (insecure)
Priority 2:  DENY  TCP  *  *  port=445   → Block SMB (ransomware)
Priority 10: ALLOW TCP  *  *  port=80    → Allow HTTP
Priority 11: ALLOW TCP  *  *  port=443   → Allow HTTPS
Priority 12: ALLOW TCP  *  *  port=22    → Allow SSH
Priority 999: DENY ANY  *  *  port=*     → Default deny all
```

### Rule Fields
| Field | Description | Wildcard |
|---|---|---|
| Action | ALLOW or DENY | — |
| Protocol | TCP, UDP, ICMP, ANY | — |
| Source IP | Source address to match | `*` |
| Dest IP | Destination address to match | `*` |
| Port | Single port, range (e.g. `8000-9000`), or any | `*` |
| Priority | 1–999 (lower = evaluated first) | — |

### Packet Tester
Enter any source IP, destination IP, protocol, and port to simulate a packet traversal through your rule chain and see exactly which rule triggers.

---

## 📊 Visualizations

1. **Port Status Donut** — Open vs Closed/Filtered breakdown
2. **Firewall Decision Donut** — ALLOWED vs DENIED among open ports
3. **Risk Map Bar Chart** — Color-coded open ports by risk level
4. **Traffic Flow Diagram** — Visual node graph of firewall routing decisions

---

## ⚖️ Legal & Ethical Notice

> ⚠️ **Only scan systems you own or have explicit written permission to test.**
>
> Unauthorized port scanning may violate laws including the Computer Fraud and Abuse Act (CFAA) in the US and similar legislation in other jurisdictions. This tool is intended for:
> - Learning and educational purposes
> - Security auditing of your own infrastructure
> - Authorized penetration testing engagements

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Streamlit |
| Scanning | python-nmap + Python `socket` fallback |
| Firewall Logic | Custom Python priority-chain engine |
| Visualization | Plotly |
| Data | Pandas |

---

## 🔧 Development Notes

- **No nmap installed?** The app automatically uses a multithreaded Python TCP connect scanner. Only TCP scans are available in fallback mode.
- **Root access needed?** SYN and UDP scans require elevated privileges. Run with `sudo streamlit run app.py` or use TCP Connect mode.
- **Extending rules?** Edit `firewall.py` → `VULNERABILITY_HINTS` and `PORT_SERVICES` to add new ports/services.

---

## 📄 License

MIT License — free for educational and personal use.

---

*Built for the Network Security course project. Demonstrates port scanning, service enumeration, firewall rule simulation, and security visualization using Python.*
