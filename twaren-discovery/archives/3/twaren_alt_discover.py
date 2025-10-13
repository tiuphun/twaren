#!/usr/bin/env python3
"""
Alternative Target Discovery for TWAREN
When direct traceroutes fail, use these methods to find working targets
"""

import subprocess
import socket
import re
from typing import List, Dict, Optional

UNIVERSITIES = {
    'NTU': 'ntu.edu.tw',
    'NDHU': 'ndhu.edu.tw',
    'NCU': 'ncu.edu.tw',
    'NTHU': 'nthu.edu.tw',
    'NYCU': 'nycu.edu.tw',
    'NCHU': 'nchu.edu.tw',
    'NCNU': 'ncnu.edu.tw',
    'CCU': 'ccu.edu.tw',
    'NCKU': 'ncku.edu.tw',
    'NSYSU': 'nsysu.edu.tw',
    'NIU': 'niu.edu.tw',
    'NCCU': 'nccu.edu.tw',
}

class AlternativeDiscovery:
    
    def get_mx_records(self, domain: str) -> List[str]:
        """Get mail servers - these usually have good connectivity"""
        try:
            result = subprocess.run(['dig', '+short', 'MX', domain],
                                  capture_output=True, text=True, timeout=10)
            mx_records = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    # MX records are "priority hostname"
                    parts = line.split()
                    if len(parts) >= 2:
                        mx_host = parts[1].rstrip('.')
                        mx_records.append(mx_host)
            return mx_records
        except:
            return []
    
    def get_ns_records(self, domain: str) -> List[str]:
        """Get nameservers - always reachable"""
        try:
            result = subprocess.run(['dig', '+short', 'NS', domain],
                                  capture_output=True, text=True, timeout=10)
            ns_records = [line.strip().rstrip('.') for line in result.stdout.strip().split('\n') if line]
            return ns_records
        except:
            return []
    
    def get_all_dns_records(self, domain: str) -> List[str]:
        """Get all A records from various subdomains"""
        common_subdomains = [
            'www', 'mail', 'smtp', 'pop', 'imap',
            'ftp', 'webmail', 'portal', 'lib', 'library',
            'vpn', 'remote', 'moodle', 'elearn',
            'cs', 'ee', 'admin', 'it', 'dns1', 'dns2'
        ]
        
        targets = []
        for sub in common_subdomains:
            hostname = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(hostname)
                targets.append(f"{hostname} -> {ip}")
            except:
                pass
        return targets
    
    def check_ping(self, target: str) -> bool:
        """Check if target responds to ping"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '2', target],
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def check_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def find_open_services(self, domain: str) -> Dict[str, List[int]]:
        """Find common open ports/services"""
        common_ports = {
            'web': [80, 443, 8080],
            'mail': [25, 587, 465, 993, 995],
            'dns': [53],
            'ssh': [22],
            'ftp': [21]
        }
        
        results = {}
        try:
            ip = socket.gethostbyname(domain)
            print(f"  Testing {domain} ({ip})...")
            
            for service, ports in common_ports.items():
                open_ports = []
                for port in ports:
                    if self.check_port(ip, port, timeout=1.0):
                        open_ports.append(port)
                if open_ports:
                    results[service] = open_ports
                    print(f"    ✓ {service}: {open_ports}")
        except:
            pass
        
        return results
    
    def discover_university(self, name: str, domain: str):
        """Comprehensive discovery for one university"""
        print(f"\n{'='*60}")
        print(f"Discovering: {name} ({domain})")
        print('='*60)
        
        results = {
            'university': name,
            'domain': domain,
            'targets': []
        }
        
        # 1. Try direct resolution
        print("\n[1] Direct DNS Resolution:")
        try:
            ip = socket.gethostbyname(domain)
            print(f"  {domain} -> {ip}")
            results['targets'].append(f"{ip} # {domain}")
        except:
            print(f"  ✗ Cannot resolve {domain}")
        
        # 2. Get MX records
        print("\n[2] Mail Servers (MX records):")
        mx_records = self.get_mx_records(domain)
        if mx_records:
            for mx in mx_records:
                try:
                    ip = socket.gethostbyname(mx)
                    print(f"  ✓ {mx} -> {ip}")
                    results['targets'].append(f"{ip} # {mx}")
                except:
                    print(f"  ✗ Cannot resolve {mx}")
        else:
            print("  No MX records found")
        
        # 3. Get NS records
        print("\n[3] Name Servers (NS records):")
        ns_records = self.get_ns_records(domain)
        if ns_records:
            for ns in ns_records:
                try:
                    ip = socket.gethostbyname(ns)
                    print(f"  ✓ {ns} -> {ip}")
                    results['targets'].append(f"{ip} # {ns}")
                except:
                    print(f"  ✗ Cannot resolve {ns}")
        else:
            print("  No NS records found")
        
        # 4. Common subdomains
        print("\n[4] Common Subdomains:")
        subdomain_targets = self.get_all_dns_records(domain)
        if subdomain_targets:
            for target in subdomain_targets[:10]:  # Show first 10
                print(f"  ✓ {target}")
                ip = target.split(' -> ')[1]
                hostname = target.split(' -> ')[0]
                results['targets'].append(f"{ip} # {hostname}")
        else:
            print("  No subdomains resolved")
        
        # 5. Open services
        print("\n[5] Open Services:")
        services = self.find_open_services(domain)
        
        # 6. Generate traceroute commands
        print("\n[6] Suggested Traceroute Commands:")
        unique_targets = list(set(results['targets']))
        if unique_targets:
            for target in unique_targets[:5]:  # Show first 5
                ip = target.split('#')[0].strip()
                comment = target.split('#')[1].strip() if '#' in target else ''
                print(f"  sudo traceroute -I {ip}  # {comment}")
        else:
            print("  No targets available for traceroute")
        
        return results
    
    def run_all(self):
        """Discover all universities"""
        print("╔════════════════════════════════════════════════════╗")
        print("║  Alternative Target Discovery for TWAREN          ║")
        print("║  Finding traceroute targets via DNS and services  ║")
        print("╚════════════════════════════════════════════════════╝\n")
        
        all_results = {}
        for name, domain in UNIVERSITIES.items():
            results = self.discover_university(name, domain)
            all_results[name] = results
        
        # Generate summary target file
        print("\n" + "="*60)
        print("SUMMARY: All Discovered Targets")
        print("="*60 + "\n")
        
        with open('alternative_targets.txt', 'w') as f:
            f.write("# Alternative TWAREN Targets\n")
            f.write("# Use these IPs for traceroute when direct domain traces fail\n\n")
            
            for name, data in all_results.items():
                if data['targets']:
                    f.write(f"\n# {name} ({data['domain']})\n")
                    print(f"\n{name}:")
                    for target in list(set(data['targets']))[:3]:
                        f.write(f"{target}\n")
                        print(f"  {target}")
        
        print("\n✓ Results saved to 'alternative_targets.txt'")
        print("\nNext steps:")
        print("  1. Review alternative_targets.txt")
        print("  2. Run traceroutes to these IPs: sudo traceroute -I <IP>")
        print("  3. Look for *.twaren.net routers in the path")

if __name__ == '__main__':
    discovery = AlternativeDiscovery()
    discovery.run_all()