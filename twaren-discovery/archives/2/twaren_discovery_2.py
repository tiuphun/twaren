#!/usr/bin/env python3
"""
TWAREN Network Infrastructure Discovery Toolkit
Automated reconnaissance for mapping Taiwan academic network from CCU
"""

import subprocess
import re
import json
import socket
from datetime import datetime
from typing import List, Dict, Optional
import concurrent.futures

# Configuration
UNIVERSITIES = {
    'NTU': ['ntu.edu.tw', 'www.ntu.edu.tw', 'mx.ntu.edu.tw'],
    'NDHU': ['ndhu.edu.tw', 'www.ndhu.edu.tw', 'mx.ndhu.edu.tw'],
    'NCU': ['ncu.edu.tw', 'www.ncu.edu.tw', 'mx.ncu.edu.tw'],
    'NTHU': ['nthu.edu.tw', 'www.nthu.edu.tw', 'mx.nthu.edu.tw'],
    'NYCU': ['nycu.edu.tw', 'www.nycu.edu.tw', 'mx.nycu.edu.tw'],
    'NCHU': ['nchu.edu.tw', 'www.nchu.edu.tw', 'mx.nchu.edu.tw'],
    'NCNU': ['ncnu.edu.tw', 'www.ncnu.edu.tw', 'mx.ncnu.edu.tw'],
    'CCU': ['ccu.edu.tw', 'www.ccu.edu.tw', 'mx.ccu.edu.tw'],
    'NCKU': ['ncku.edu.tw', 'www.ncku.edu.tw', 'mx.ncku.edu.tw'],
    'NSYSU': ['nsysu.edu.tw', 'www.nsysu.edu.tw', 'mx.nsysu.edu.tw'],
    'NIU': ['niu.edu.tw', 'www.niu.edu.tw', 'mx.niu.edu.tw'],
    'NCCU': ['nccu.edu.tw', 'www.nccu.edu.tw', 'mx.nccu.edu.tw'],
}

CORE_NODES = {
    'SINICA': ['sinica.edu.tw', 'www.sinica.edu.tw'],
    'NCHC': ['nchc.org.tw', 'www.nchc.org.tw', 'twaren.net'],
}

# Common gateway naming patterns
GATEWAY_PATTERNS = [
    'gw', 'gateway', 'border', 'br', 'edge',
    'twaren', 'core', 'router', 'rt', 'gw1', 'gw2'
]

class TWARENDiscovery:
    def __init__(self, output_file='twaren_discovery.json'):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'source': 'CCU',
            'dns_lookups': {},
            'traceroutes': {},
            'discovered_ips': {},
            'potential_gateways': []
        }
        self.output_file = output_file
    
    def dns_lookup(self, hostname: str) -> Optional[str]:
        """Perform DNS lookup for a hostname"""
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.gaierror:
            return None
    
    def reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def try_gateway_names(self, domain: str) -> Dict[str, str]:
        """Try common gateway naming patterns"""
        results = {}
        for pattern in GATEWAY_PATTERNS:
            hostname = f"{pattern}.{domain}"
            ip = self.dns_lookup(hostname)
            if ip:
                results[hostname] = ip
                print(f"  ✓ Found: {hostname} -> {ip}")
        return results
    
    def run_traceroute(self, target: str, use_icmp=True) -> List[Dict]:
        """Run traceroute and parse output"""
        cmd = ['traceroute']
        if use_icmp:
            cmd.append('-I')
        cmd.extend(['-m', '30', '-w', '2', target])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return self.parse_traceroute(result.stdout)
        except subprocess.TimeoutExpired:
            print(f"  ⚠ Traceroute to {target} timed out")
            return []
        except Exception as e:
            print(f"  ✗ Error running traceroute to {target}: {e}")
            return []
    
    def parse_traceroute(self, output: str) -> List[Dict]:
        """Parse traceroute output to extract hops"""
        hops = []
        lines = output.strip().split('\n')[1:]  # Skip header
        
        for line in lines:
            # Match hop number, hostname/IP, and latency
            match = re.match(r'\s*(\d+)\s+([^\s]+)\s+\(([^)]+)\)', line)
            if match:
                hop_num = int(match.group(1))
                hostname = match.group(2)
                ip = match.group(3)
                
                # Check if this looks like a TWAREN router
                is_gateway = any(pattern in hostname.lower() 
                               for pattern in ['twaren', 'gw', 'border', 'core', 'br'])
                
                hop_info = {
                    'hop': hop_num,
                    'hostname': hostname,
                    'ip': ip,
                    'is_potential_gateway': is_gateway
                }
                hops.append(hop_info)
                
                if is_gateway:
                    print(f"    🎯 Potential gateway: {hostname} ({ip})")
        
        return hops
    
    def discover_dns(self):
        """Phase 1: DNS discovery"""
        print("\n=== Phase 1: DNS Discovery ===\n")
        
        all_nodes = {**UNIVERSITIES, **CORE_NODES}
        
        for node_name, domains in all_nodes.items():
            print(f"Discovering {node_name}...")
            node_results = {}
            
            for domain in domains:
                ip = self.dns_lookup(domain)
                if ip:
                    node_results[domain] = ip
                    reverse = self.reverse_dns(ip)
                    if reverse:
                        node_results[f"{domain}_reverse"] = reverse
                    print(f"  {domain} -> {ip}")
                
                # Try gateway patterns
                gw_results = self.try_gateway_names(domain.split('www.')[-1])
                node_results.update(gw_results)
            
            self.results['dns_lookups'][node_name] = node_results
    
    def get_traceroute_targets(self, node_name: str) -> List[str]:
        """Get multiple traceroute targets for a node, including IPs from DNS discovery"""
        targets = []
        
        # First, try to use IPs we discovered in DNS phase
        if node_name in self.results['dns_lookups']:
            for hostname, ip in self.results['dns_lookups'][node_name].items():
                if not hostname.endswith('_reverse') and ip:
                    targets.append(ip)
        
        # Add common service endpoints
        all_nodes = {**UNIVERSITIES, **CORE_NODES}
        if node_name in all_nodes:
            base_domains = all_nodes[node_name]
            for domain in base_domains:
                # Try web server
                targets.append(f"www.{domain}" if not domain.startswith('www') else domain)
                # Try mail server
                targets.append(f"mail.{domain}")
                targets.append(f"mx.{domain}")
                # Try FTP (some universities have it)
                targets.append(f"ftp.{domain}")
                # Try library (often has good connectivity)
                targets.append(f"lib.{domain}")
                targets.append(f"library.{domain}")
        
        return targets
    
    def discover_traceroutes(self, max_workers=3):
        """Phase 2: Traceroute discovery with multiple targets per node"""
        print("\n=== Phase 2: Traceroute Discovery ===\n")
        
        all_nodes = list(UNIVERSITIES.keys()) + list(CORE_NODES.keys())
        
        for node_name in all_nodes:
            print(f"\nTracing routes to {node_name}...")
            targets = self.get_traceroute_targets(node_name)
            
            node_results = []
            successful_trace = False
            
            for target in targets[:5]:  # Try up to 5 targets per node
                if successful_trace:
                    break
                
                print(f"  Attempting: {target}")
                hops = self.run_traceroute(target)
                
                if hops and len(hops) > 2:  # At least 3 hops means we got something useful
                    successful_trace = True
                    node_results.append({
                        'target': target,
                        'hops': hops,
                        'status': 'success'
                    })
                    print(f"    ✓ Success: {len(hops)} hops discovered")
                    
                    # Collect potential gateways
                    for hop in hops:
                        if hop['is_potential_gateway']:
                            # Check if we already have this gateway
                            if not any(gw['ip'] == hop['ip'] for gw in self.results['potential_gateways']):
                                self.results['potential_gateways'].append({
                                    'node': node_name,
                                    'hostname': hop['hostname'],
                                    'ip': hop['ip'],
                                    'hop_number': hop['hop']
                                })
                else:
                    node_results.append({
                        'target': target,
                        'hops': [],
                        'status': 'failed'
                    })
            
            if not successful_trace:
                print(f"  ⚠ All targets failed for {node_name}")
            
            self.results['traceroutes'][node_name] = node_results
    
    def analyze_results(self):
        """Phase 3: Analyze and summarize findings"""
        print("\n=== Phase 3: Analysis ===\n")
        
        # Extract unique IPs
        all_ips = set()
        for node_data in self.results['dns_lookups'].values():
            for key, value in node_data.items():
                if not key.endswith('_reverse') and '.' in value:
                    all_ips.add(value)
        
        for trace_data in self.results['traceroutes'].values():
            for hop in trace_data['hops']:
                all_ips.add(hop['ip'])
        
        self.results['discovered_ips'] = {
            'total_unique_ips': len(all_ips),
            'ips': sorted(list(all_ips))
        }
        
        print(f"Total unique IPs discovered: {len(all_ips)}")
        print(f"Potential gateways found: {len(self.results['potential_gateways'])}")
        
        # Group gateways by IP subnet
        subnets = {}
        for gw in self.results['potential_gateways']:
            subnet = '.'.join(gw['ip'].split('.')[:3]) + '.0/24'
            if subnet not in subnets:
                subnets[subnet] = []
            subnets[subnet].append(gw)
        
        print("\nPotential Gateway Subnets:")
        for subnet, gateways in sorted(subnets.items()):
            print(f"  {subnet}: {len(gateways)} gateway(s)")
            for gw in gateways[:3]:  # Show first 3
                print(f"    - {gw['hostname']} ({gw['ip']})")
    
    def save_results(self):
        """Save results to JSON file"""
        with open(self.output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n✓ Results saved to {self.output_file}")
    
    def generate_target_list(self, output_file='twaren_targets.txt'):
        """Generate a clean list of target IPs for further testing"""
        targets = set()
        
        # Add all potential gateways
        for gw in self.results['potential_gateways']:
            targets.add(f"{gw['ip']}\t# {gw['node']} - {gw['hostname']}")
        
        # Add discovered gateway IPs from DNS
        for node_name, lookups in self.results['dns_lookups'].items():
            for hostname, ip in lookups.items():
                if not hostname.endswith('_reverse'):
                    if any(p in hostname for p in GATEWAY_PATTERNS):
                        targets.add(f"{ip}\t# {node_name} - {hostname}")
        
        with open(output_file, 'w') as f:
            f.write("# TWAREN Target IPs for Network Mapping\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Source: CCU\n\n")
            for target in sorted(targets):
                f.write(target + '\n')
        
        print(f"✓ Target list saved to {output_file}")
    
    def run_full_discovery(self):
        """Run complete discovery process"""
        print("╔════════════════════════════════════════╗")
        print("║  TWAREN Network Discovery Toolkit     ║")
        print("║  Source: National Chung Cheng Univ.   ║")
        print("╚════════════════════════════════════════╝")
        
        self.discover_dns()
        self.discover_traceroutes()
        self.analyze_results()
        self.save_results()
        self.generate_target_list()
        
        print("\n✓ Discovery complete!")

if __name__ == '__main__':
    import sys
    
    # Check if running as root for ICMP traceroute
    if subprocess.run(['id', '-u'], capture_output=True).stdout.decode().strip() != '0':
        print("⚠ Warning: Not running as root. ICMP traceroute may not work.")
        print("  Consider running with: sudo python3 twaren_discovery.py")
        print("  Or traceroute will fall back to UDP.\n")
    
    discovery = TWARENDiscovery()
    discovery.run_full_discovery()