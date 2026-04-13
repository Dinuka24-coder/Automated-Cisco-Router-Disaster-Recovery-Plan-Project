from netmiko import ConnectHandler
from datetime import datetime
import time

start_time = time.time()

cisco_router = {
    'device_type': 'cisco_ios',
    'host':        'devnetsandboxiosxec8k.cisco.com',
    'username':    'amarasekaradinuka25',
    'password':    'QntC5ZG4--d0',
    'port':        22,
    'global_delay_factor': 2, 
}

print(f"Connecting to {cisco_router['host']}... (this may take up to 30 seconds)")

try:
    net_connect = ConnectHandler(**cisco_router)
    print("\nSuccess! Logged in successfully.")
    
    print("Retrieving the running configuration...")
    output = net_connect.send_command("show running-config")
    
    date_str = datetime.now().strftime("%Y-%m-%d")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    backup_filename = f"backup_router_{date_str}.txt"
    audit_filename = f"security_audit_{date_str}.txt"
    
    with open(backup_filename, "w") as backup_file:
        backup_file.write(output)
    print(f"Awesome! Backup successfully saved as: {backup_filename}")
    
    # =================================================================
    # ENHANCED SECURITY AUDIT SECTION
    # =================================================================
    print("\n--- Initiating Deep-Scan Security Audit ---")
    
    security_alerts = []
    lines = output.splitlines()
    total_lines = len(lines)
    
    # Check flags for configurations that should exist but might be missing
    has_banner = False
    has_syslog = False
    has_ntp = False

    for line_num, line in enumerate(lines, 1):
        line = line.strip().lower()
        
        # 1. Password Vulnerabilities
        if line.startswith("enable password"):
            security_alerts.append(f"[Line {line_num:03d}] [HIGH]   Plaintext 'enable password' found. Action: Use 'enable secret'.")
        if "password 7 " in line:
            security_alerts.append(f"[Line {line_num:03d}] [MEDIUM] Weak Type 7 encryption detected. Action: Upgrade hashing algorithm.")
        if line == "no service password-encryption":
            security_alerts.append(f"[Line {line_num:03d}] [HIGH]   Global password encryption disabled. Action: Enable immediately.")
            
        # 2. Access and Management Protocols
        if "snmp-server community public" in line or "snmp-server community private" in line:
            security_alerts.append(f"[Line {line_num:03d}] [CRITICAL] Default SNMP string active. Action: Change community string.")
        if "transport input telnet" in line or "transport input all" in line:
            security_alerts.append(f"[Line {line_num:03d}] [CRITICAL] Insecure Telnet transport permitted. Action: Restrict to SSH only.")
        if line == "ip http server":
            security_alerts.append(f"[Line {line_num:03d}] [MEDIUM] Unencrypted HTTP web dashboard enabled. Action: Use 'ip http secure-server'.")
            
        # 3. Network Architecture Flaws
        if "permit ip any any" in line:
            security_alerts.append(f"[Line {line_num:03d}] [CRITICAL] 'Any-to-Any' ACL detected. Action: Restrict firewall rules.")
            
        # Track presence of required best-practices
        if "banner motd" in line or "banner login" in line: has_banner = True
        if "logging host" in line or "logging trap" in line: has_syslog = True
        if "ntp server" in line: has_ntp = True

    # Check for missing best practices
    if not has_banner:
        security_alerts.append(f"[Global]  [LOW]    No legal warning banner (MOTD) configured. Action: Add legal login warning.")
    if not has_syslog:
        security_alerts.append(f"[Global]  [HIGH]   No centralized Syslog server configured. Action: Configure logging host for SIEM.")
    if not has_ntp:
        security_alerts.append(f"[Global]  [MEDIUM] No NTP server configured. Log timestamps will be inaccurate. Action: Add NTP server.")

    # Generate the formatted Enterprise Report
    if security_alerts:
        print(f"⚠️  WARNING: {len(security_alerts)} security vulnerabilities found!\n")
        
        with open(audit_filename, "w") as audit_file:
            # 1. Metadata Header
            audit_file.write("="*75 + "\n")
            audit_file.write("               ENTERPRISE NETWORK SECURITY AUDIT REPORT\n")
            audit_file.write("="*75 + "\n")
            audit_file.write(f"Target Device  : {cisco_router['host']}\n")
            audit_file.write(f"Device OS      : Cisco IOS/IOS-XE\n")
            audit_file.write(f"Audit Date     : {timestamp}\n")
            audit_file.write("-" * 75 + "\n")
            
            # 2. Executive Summary
            audit_file.write("EXECUTIVE SUMMARY:\n")
            audit_file.write(f"Lines Scanned  : {total_lines} lines of running-config\n")
            audit_file.write(f"Vulnerabilities: {len(security_alerts)} issues detected requiring remediation\n")
            audit_file.write("-" * 75 + "\n")
            
            # 3. Detailed Findings
            audit_file.write("DETAILED VULNERABILITY FINDINGS:\n\n")
            for alert in security_alerts:
                print(f" - {alert}")
                audit_file.write(f"{alert}\n")
            
            # 4. Footer
            audit_file.write("\n" + "="*75 + "\n")
            audit_file.write("END OF REPORT. Please forward to the Network Security Team for remediation.\n")
            audit_file.write("="*75 + "\n")
                
        print(f"\nDetailed enterprise security report saved as: {audit_filename}")
    else:
        print("✅ SUCCESS: No vulnerabilities detected.")

    net_connect.disconnect()
    end_time = time.time()
    execution_time = round(end_time - start_time, 2)
    print(f"\n[Operation completed in {execution_time} seconds]")

except Exception as e:
    print(f"\nScript failed. Error details: {e}")