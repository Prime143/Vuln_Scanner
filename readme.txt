# 🛡️ Network Security Dashboard

Interactive SOC-style terminal dashboard to discover hosts, assess vulnerabilities, and generate remediation reports — powered by Nmap and Python. Supports both numeric menu commands and natural language like “find vulnerabilities in my network” or “generate a report.”

## ✨ Features

- ⚡ Network discovery (Nmap ping sweep)
- 🧠 Vulnerability assessment per host (service-based heuristics)
- 🧰 Executive summary with risk levels
- 📝 One-click report generation (text report)
- 🗣️ Natural language commands (e.g., “scan my network”, “what can you do?”)
- 🧾 Scan history in-memory (optional: persistence ready)
- 🖥️ Clean interactive dashboard UI

## 🧮 How It Works

1. Discover hosts on a target network using Nmap `-sn`.
2. Scan selected hosts using Nmap `-sV -A` (service + version detection).
3. Parse services and match against a lightweight vulnerability knowledge base.
4. Score severities and compute overall risk.
5. Generate an executive summary and detailed text reports.


## 🛠️ Requirements

- Python 3.8+
- Nmap (CLI)
- Linux/macOS/WSL recommended (Windows works if Nmap in PATH)

Install Nmap:
- Debian/Ubuntu/Kali: `sudo apt update && sudo apt install -y nmap`
- macOS (Homebrew): `brew install nmap`
- Windows: https://nmap.org/download.html (add to PATH)

Python packages:
- Standard library only for the base version (json, subprocess, datetime, os, time).
- If you later add extras (PDF, rich TUI, etc.), track them in requirements.txt.


4) Use numbers or natural language:
- “scan” or “1” → Full network security scan
- “discover” or “2” → Quick network discovery
- “history” or “3” → View scan history
- “report” or “4” → Generate report from latest scan
- “config” or “5” → Change target network
- “recommend” or “6” → Best practices
- “status” or “7” → System status
- “help” → Show help
- “exit” or “0” → Quit

Tip: On first run, set the target network in “config” if different from the default.

## 🧪 Example Commands

- “scan my network and generate a report”
- “find vulnerabilities and how to fix them”
- “show previous scans”
- “change network to 10.0.0.0/24”
- “help”

## 📄 Output

- Reports saved to: `reports/security_report_YYYYMMDD_HHMMSS.txt`
- Sample contents:
  - Executive summary (risk level, hosts scanned, vulnerability counts)
  - Severity distribution (Critical/High/Medium/Low)
  - Host-level findings
  - Top recommendations

## 🔒 Permissions & Notes

- Some scans may require elevated permissions depending on your OS and Nmap features.
- Respect legal and ethical guidelines: only scan networks you own or have permission to test.
- For faster scans, limit host count and/or ports.

## 🧭 Roadmap

- Persist scan history to disk (JSON) and load on startup
- Export reports in Markdown/PDF with richer formatting
- Add configurable scan profiles (fast, full, custom ports)
- Add CVE/CPE enrichment (optional future module)
- Improve TUI (progress bars, colors)

## 🤝 Contributing

Pull requests welcome:
- Fork the repo
- Create a feature branch
- Commit changes with clear messages
- Open a PR describing the change

## 🐛 Troubleshooting

- “nmap: command not found” → Install Nmap and ensure it’s in PATH.
- “Permission denied” → Try running with appropriate privileges or adjust Nmap flags.
- “No hosts found” → Validate the target network range in “config”.

## 📜 License

MIT License — see LICENSE.

## 🙌 Credits

Built with Python and Nmap. Inspired by SOC workflows and practical network security tooling.
