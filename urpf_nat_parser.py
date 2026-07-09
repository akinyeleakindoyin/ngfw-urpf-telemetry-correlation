import re

def parse_logs(syslog_path, nat_path):
    print("[*] Beginning Telemetry Correlation Engine...")
    
    # Simple patterns matching our sanitized structures
    syslog_pattern = r"Deny TCP reverse path check from (?P<src_ip>[\d\.]+) to (?P<dst_ip>[\d\.]+) on interface"
    nat_pattern = r"TCP PAT from Inside:(?P<int_ip>[\d\.]+)/(?P<int_port>\d+) to Outside:(?P<ext_ip>[\d\.]+)/(?P<ext_port>\d+)"
    
    with open(syslog_path, 'r') as f:
        syslogs = f.readlines()
        
    with open(nat_path, 'r') as f:
        nat_entries = f.readlines()

    for log in syslogs:
        log_match = re.search(syslog_pattern, log)
        if log_match:
            dropped_ip = log_match.group('src_ip')
            
            # Search NAT table for active ephemeral mapping
            for entry in nat_entries:
                nat_match = re.search(nat_pattern, entry)
                if nat_match and nat_match.group('ext_ip') == dropped_ip:
                    print(f"\n[!] MATCH FOUND")
                    print(f"[-] Firewall dropped an external packet from: {dropped_ip}")
                    print(f"[+] Root Cause: This maps directly to Internal Host: {nat_match.group('int_ip')} via Ephemeral Port: {nat_match.group('int_port')}")

if __name__ == "__main__":
    parse_logs("sanitized_syslog.log", "nat_table.txt")
