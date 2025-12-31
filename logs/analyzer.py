import pandas as pd
import re

AUTH_LOG = r"F:\BlueCrossAnalyzer\logs\auth.log"
IDS_LOG = r"F:\BlueCrossAnalyzer\logs\ids.log"
FW_LOG = r"F:\BlueCrossAnalyzer\logs\firewall.log"

ALERT_KEYWORDS = ["failed login", "alert", "malware", "blocked", "port scan"]

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def load_log(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    df = pd.DataFrame([line.strip() for line in lines if line.strip()], columns=['log'])
    return df

def detect_suspicious(df):
    alerts = df[df['log'].str.contains('|'.join(ALERT_KEYWORDS), case=False)]
    print(f"{YELLOW}Matching {len(alerts)} lines for keywords {ALERT_KEYWORDS}{RESET}")
    return alerts

def extract_ips(df):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    df['ip'] = df['log'].apply(lambda x: re.findall(ip_pattern, x))
    df = df.explode('ip').dropna()
    return df

def cross_analyse(df1, df2):
    common_ips = pd.merge(df1, df2, on='ip', how='inner')
    return common_ips

if __name__ == "__main__":
    auth_df = load_log(AUTH_LOG)
    ids_df = load_log(IDS_LOG)
    fw_df = load_log(FW_LOG)

    print(f"{YELLOW}Auth logs loaded: {auth_df.shape[0]} entries{RESET}")
    print(f"{YELLOW}IDS logs loaded: {ids_df.shape[0]} entries{RESET}")
    print(f"{YELLOW}Firewall logs loaded: {fw_df.shape[0]} entries{RESET}\n")

    auth_alerts = detect_suspicious(auth_df)
    ids_alerts = detect_suspicious(ids_df)
    fw_alerts = detect_suspicious(fw_df)

    auth_ips = extract_ips(auth_alerts)
    ids_ips = extract_ips(ids_alerts)
    fw_ips = extract_ips(fw_alerts)

    cross_ips = cross_analyse(auth_ips, ids_ips)
    cross_ips = cross_analyse(cross_ips, fw_ips)

    print(f"{GREEN}Summary of suspicious activities:{RESET}")
    print(f"Failed logins: {len(auth_alerts)}")
    print(f"IDS alerts: {len(ids_alerts)}")
    print(f"Firewall blocks: {len(fw_alerts)}\n")

    cross_ips.to_csv(r"F:\BlueCrossAnalyzer\reports\report.txt", index=False, sep='\t')
    print(f"{GREEN}[+] Analysis complete. Report saved to reports/report.txt{RESET}")
