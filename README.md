# BlueCrossAnalyzer
A Python-based log analysis tool for blue teaming tasks.
This project analyzes authentication logs, IDS alerts, and firewall logs
to detect suspicious activity and cross-check IP addresses. It helps in
basic threat detection by generating a summary and report of suspicious events.
## Features
- Parses authentication logs, IDS logs, and firewall logs
- Detects patterns such as failed logins, alerts, and blocked activity
- Extracts and cross-matches suspicious IPs
- Generates a summary report in `reports/report.txt`
## How to Run
1. Clone the repository  
   ```bash
   git clone https://github.com/BabluCSE111/BlueCrossAnalyzer.git
