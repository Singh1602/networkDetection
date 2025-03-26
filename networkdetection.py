import socket
import nmap
import logging
from scapy.all import *
from datetime import datetime
import subprocess
import json
import requests
import threading
from queue import Queue

# Configure logging
logging.basicConfig(
    filename='/root/security_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class NetworkSecurityMonitor:
    def __init__(self):
        self.suspicious_ips = set()
        self.attack_counts = {}
        self.port_scan_threshold = 10
        self.syn_flood_threshold = 100
        self.blocked_ips = set()
        
    def port_scan(self, target):
        nm = nmap.PortScanner()
        try:
            scan_results = nm.scan(target, arguments='-sV -sC -p-')
            for host in scan_results['scan']:
                for port in scan_results['scan'][host]['tcp']:
                    service = scan_results['scan'][host]['tcp'][port]
                    # Check against NVD database
                    self.check_vulnerabilities(service['name'], service['version'])
                    logging.info(f"Port {port}: {service['name']} {service['version']}")
        except Exception as e:
            logging.error(f"Port scan error: {str(e)}")

    def check_vulnerabilities(self, service, version):
        nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service}%20{version}"
        try:
            response = requests.get(nvd_api_url)
            vulns = response.json()
            for vuln in vulns.get('result', {}).get('CVE_Items', []):
                logging.warning(f"Vulnerability found: {vuln['cve']['CVE_ID']}")
        except Exception as e:
            logging.error(f"Vulnerability check error: {str(e)}")

    def detect_syn_flood(self, packet):
        if TCP in packet and packet[TCP].flags == 'S':
            src_ip = packet[IP].src
            self.attack_counts[src_ip] = self.attack_counts.get(src_ip, 0) + 1
            if self.attack_counts[src_ip] > self.syn_flood_threshold:
                self.block_ip(src_ip)
                logging.warning(f"SYN flood detected from {src_ip}")

    def detect_arp_spoofing(self, packet):
        if ARP in packet:
            if packet[ARP].op == 2:  # ARP reply
                real_mac = getmacbyip(packet[ARP].psrc)
                if real_mac and real_mac != packet[ARP].hwsrc:
                    attacker_mac = packet[ARP].hwsrc
                    logging.warning(f"ARP spoofing detected! Attacker MAC: {attacker_mac}")
                    self.block_mac(attacker_mac)

    def detect_dns_poisoning(self, packet):
        if DNS in packet and packet.haslayer(DNSRR):
            for i in range(packet[DNS].ancount):
                dnsrr = packet[DNS].an[i]
                if dnsrr.type == 1:  # A record
                    if self.is_suspicious_dns(dnsrr.rdata):
                        logging.warning(f"Suspicious DNS response detected: {dnsrr.rrname} -> {dnsrr.rdata}")

    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            try:
                if os.name == 'nt':  # Windows
                    subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                                 f'name="Block {ip}"', 'dir=in', 'action=block',
                                 f'remoteip={ip}'])
                else:  # Linux
                    subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
                self.blocked_ips.add(ip)
                logging.info(f"Blocked IP: {ip}")
            except Exception as e:
                logging.error(f"Failed to block IP {ip}: {str(e)}")

    def block_mac(self, mac):
        try:
            if os.name == 'nt':  # Windows
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                             f'name="Block {mac}"', 'dir=in', 'action=block',
                             f'remoteip={mac}'])
            else:  # Linux
                subprocess.run(['ebtables', '-A', 'INPUT', '-s', mac, '-j', 'DROP'])
            logging.info(f"Blocked MAC: {mac}")
        except Exception as e:
            logging.error(f"Failed to block MAC {mac}: {str(e)}")

    def generate_report(self):
        report = {
            'timestamp': datetime.now().isoformat(),
            'blocked_ips': list(self.blocked_ips),
            'attack_counts': self.attack_counts,
            'suspicious_ips': list(self.suspicious_ips)
        }
        with open('security_report.json', 'w') as f:
            json.dump(report, f, indent=4)
        logging.info("Security report generated")

    def start_monitoring(self):
        try:
            # Start packet capture
            sniff(prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            self.generate_report()
            logging.info("Monitoring stopped")

    def packet_handler(self, packet):
        if IP in packet:
            # Run all detection methods
            self.detect_syn_flood(packet)
            self.detect_arp_spoofing(packet)
            self.detect_dns_poisoning(packet)

def main():
    monitor = NetworkSecurityMonitor()
    print("Starting Network Security Monitoring...")
    
    # Start monitoring in a separate thread
    monitor_thread = threading.Thread(target=monitor.start_monitoring)
    monitor_thread.start()
    
    try:
        while True:
            # Generate report every hour
            time.sleep(3600)
            monitor.generate_report()
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        monitor.generate_report()

if __name__ == '__main__':
    print("Running Progamme ")
