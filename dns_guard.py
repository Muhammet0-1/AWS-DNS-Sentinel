import boto3
import json
import logging
import os
from datetime import datetime

# === AWS DNS Sentinel (Formerly IronGate Cloud) ===
# Developed by: LordMs
# Purpose: Detect and remediate Dangling DNS & Subdomain Takeover

# Logging Configuration
logging.basicConfig(
    filename='dns_sentinel.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DNSIntegrityScanner:
    """
    Cloud Security Suite - DNS Integrity & Automation
    Developed for proactive threat detection and auto-remediation.
    """
    def __init__(self, zone_id):
        # AWS bağlantısı için boto3 (Credentials ~/.aws/credentials dosyasından çekilir)
        self.r53 = boto3.client('route53')
        self.zone_id = zone_id
        self.baseline_file = 'dns_baseline.json'

    def fetch_current_state(self):
        """Retrieves all resource record sets from the hosted zone."""
        records = []
        paginator = self.r53.get_paginator('list_resource_record_sets')
        try:
            for page in paginator.paginate(HostedZoneId=self.zone_id):
                for r in page['ResourceRecordSets']:
                    records.append({
                        'Name': r['Name'],
                        'Type': r['Type'],
                        'Value': [v['Value'] for v in r.get('ResourceRecords', [])],
                        'TTL': r.get('TTL', 300)
                    })
            return records
        except Exception as e:
            print(f"[!] AWS Connection Error: {e}")
            return []

    def initialize_baseline(self):
        """Sets the trusted configuration baseline for future audits."""
        print("[*] Establishing secure baseline...")
        state = self.fetch_current_state()
        if state:
            with open(self.baseline_file, 'w') as f:
                json.dump(state, f, indent=4)
            print(f"[+] Secure baseline established in {self.baseline_file}.")
            logging.info("New baseline initialized.")
        else:
            print("[-] No records found or connection failed.")

    def perform_audit(self):
        """Scans for unauthorized changes and triggers auto-remediation if needed."""
        print(f"\n--- [ DNS Sentinel Scan Started: {datetime.now()} ] ---")
        
        if not os.path.exists(self.baseline_file):
            print("[!] Baseline not found. Initializing first...")
            self.initialize_baseline()
            return

        with open(self.baseline_file, 'r') as f:
            baseline = json.load(f)
        
        current_state = self.fetch_current_state()
        # Basitleştirilmiş karşılaştırma için isim listesi
        current_names = {r['Name']: r for r in current_state}
        
        violation_count = 0

        # Check for modified or missing records
        for trusted_record in baseline:
            r_name = trusted_record['Name']
            
            # 1. Kayıt Silinmiş mi? (Dangling DNS Riski)
            if r_name not in current_names:
                violation_count += 1
                msg = f"CRITICAL: Record missing! {r_name} ({trusted_record['Type']})"
                print(f"🚨 {msg}")
                logging.warning(msg)
                self.remediate_threat(trusted_record)
                continue
            
            # 2. Kayıt Değiştirilmiş mi? (Subdomain Takeover Riski)
            current_val = current_names[r_name]['Value']
            trusted_val = trusted_record['Value']
            
            # Listeleri sıralayıp karşılaştır (sıra farkı hata vermesin diye)
            if sorted(current_val) != sorted(trusted_val):
                violation_count += 1
                msg = f"INTEGRITY VIOLATION: {r_name} modified! New: {current_val}"
                print(f"🚨 {msg}")
                logging.warning(msg)
                self.remediate_threat(trusted_record)

        if violation_count == 0:
            print("🛡️ Scan Complete: No deviations detected. System is secure.")
        else:
            print(f"⚠️ Result: {violation_count} unauthorized changes detected and remediated.")

    def remediate_threat(self, trusted_record):
        """Automatically restores the DNS record to its trusted baseline state."""
        print(f"🔄 [Auto-Healing] Reverting {trusted_record['Name']} to baseline...")
        try:
            self.r53.change_resource_record_sets(
                HostedZoneId=self.zone_id,
                ChangeBatch={'Changes': [{
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': trusted_record['Name'],
                        'Type': trusted_record['Type'],
                        'TTL': trusted_record.get('TTL', 300),
                        'ResourceRecords': [{'Value': v} for v in trusted_record['Value']]
                    }
                }]}
            )
            logging.info(f"Remediation successful for {trusted_record['Name']}")
            print(f"✅ [Fixed] {trusted_record['Name']} has been restored.")
        except Exception as e:
            print(f"❌ [Error] Failed to remediate {trusted_record['Name']}: {e}")
            logging.error(f"Remediation failed: {e}")

if __name__ == "__main__":
    # Example Zone ID (Would be passed as arg in production)
    TARGET_ZONE = 'Z028096516P1N2GX2H5U1' 
    
    print("Initializing AWS DNS Sentinel...")
    scanner = DNSIntegrityScanner(TARGET_ZONE)
    
    # Mode selection
    # scanner.initialize_baseline() # İlk kullanımda açılır
    scanner.perform_audit()         # Cronjob ile sürekli çalışır
