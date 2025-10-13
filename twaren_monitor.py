#!/usr/bin/env python3
"""
TWAREN Route Monitoring System
Tracks route changes over time, identifies core infrastructure, and analyzes routing stability
"""

import subprocess
import json
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from collections import defaultdict, Counter
import statistics

class RouteMonitor:
    def __init__(self, data_dir='route_data'):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.results_file = self.data_dir / 'all_traces.jsonl'  # JSON Lines format
        
    def load_targets(self, target_file='twaren_targets.txt') -> Dict[str, str]:
        """Load target IPs from file"""
        targets = {}
        try:
            with open(target_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Format: IP # comment
                        parts = line.split('#')
                        ip = parts[0].strip()
                        comment = parts[1].strip() if len(parts) > 1 else ip
                        targets[ip] = comment
        except FileNotFoundError:
            print(f"⚠ Target file {target_file} not found")
        
        return targets
    
    def parse_traceroute_output(self, output: str) -> List[Dict]:
        """Parse traceroute output into structured hops"""
        hops = []
        lines = output.strip().split('\n')
        
        # Skip header
        if lines and 'traceroute to' in lines[0]:
            lines = lines[1:]
        
        for line in lines:
            if not line.strip():
                continue
            
            # Match hop number
            hop_match = re.match(r'\s*(\d+)\s+(.+)', line)
            if not hop_match:
                continue
            
            hop_num = int(hop_match.group(1))
            rest = hop_match.group(2)
            
            # Check for timeout
            if '* * *' in rest:
                hops.append({
                    'hop': hop_num,
                    'hostname': '*',
                    'ip': '*',
                    'rtt': None
                })
                continue
            
            # Extract hostname, IP, and RTT
            # Pattern: hostname (ip) rtt ms
            pattern = r'([^\s]+)\s+\(([0-9.]+)\)\s+([0-9.]+)\s+ms'
            matches = re.findall(pattern, rest)
            
            if matches:
                # Take first match (in case of multiple responses per hop)
                hostname, ip, rtt = matches[0]
                hops.append({
                    'hop': hop_num,
                    'hostname': hostname,
                    'ip': ip,
                    'rtt': float(rtt)
                })
        
        return hops
    
    def run_single_trace(self, target_ip: str, target_name: str) -> Dict:
        """Run a single traceroute and return structured result"""
        timestamp = datetime.now()
        
        try:
            cmd = ['traceroute', '-I', '-m', '25', '-w', '2', target_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            hops = self.parse_traceroute_output(result.stdout)
            
            return {
                'timestamp': timestamp.isoformat(),
                'target_ip': target_ip,
                'target_name': target_name,
                'hops': hops,
                'hop_count': len(hops),
                'success': len(hops) > 0
            }
        
        except subprocess.TimeoutExpired as e:
            partial_output = e.stdout.decode() if e.stdout else ""
            hops = self.parse_traceroute_output(partial_output)
            
            return {
                'timestamp': timestamp.isoformat(),
                'target_ip': target_ip,
                'target_name': target_name,
                'hops': hops,
                'hop_count': len(hops),
                'success': len(hops) > 0,
                'timeout': True
            }
        
        except Exception as e:
            return {
                'timestamp': timestamp.isoformat(),
                'target_ip': target_ip,
                'target_name': target_name,
                'hops': [],
                'hop_count': 0,
                'success': False,
                'error': str(e)
            }
    
    def run_trace_cycle(self, targets: Dict[str, str], delay_between=2):
        """Run traceroute to all targets and save results"""
        cycle_start = datetime.now()
        print(f"\n{'='*70}")
        print(f"Starting trace cycle at {cycle_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        results = []
        
        for i, (target_ip, target_name) in enumerate(targets.items(), 1):
            print(f"[{i}/{len(targets)}] Tracing to {target_name} ({target_ip})...", end=' ')
            
            trace_result = self.run_single_trace(target_ip, target_name)
            results.append(trace_result)
            
            if trace_result['success']:
                print(f"✓ {trace_result['hop_count']} hops")
            else:
                print(f"✗ Failed")
            
            # Delay between traces to avoid overwhelming the network
            if i < len(targets):
                time.sleep(delay_between)
        
        # Save results in JSON Lines format (one JSON object per line)
        with open(self.results_file, 'a') as f:
            for result in results:
                f.write(json.dumps(result) + '\n')
        
        cycle_end = datetime.now()
        duration = (cycle_end - cycle_start).total_seconds()
        
        print(f"\n✓ Cycle complete in {duration:.1f}s")
        print(f"  Results appended to {self.results_file}")
        
        return results
    
    def load_all_traces(self) -> List[Dict]:
        """Load all historical trace data"""
        traces = []
        if self.results_file.exists():
            with open(self.results_file, 'r') as f:
                for line in f:
                    if line.strip():
                        traces.append(json.loads(line))
        return traces
    
    def analyze_route_stability(self, target_ip: str = None) -> Dict:
        """Analyze how stable routes are over time"""
        traces = self.load_all_traces()
        
        if not traces:
            return {'error': 'No trace data available'}
        
        # Filter by target if specified
        if target_ip:
            traces = [t for t in traces if t['target_ip'] == target_ip]
        
        # Group traces by target
        by_target = defaultdict(list)
        for trace in traces:
            by_target[trace['target_ip']].append(trace)
        
        analysis = {}
        
        for target, target_traces in by_target.items():
            target_name = target_traces[0]['target_name']
            
            # Extract all unique routes (as tuple of IPs)
            routes = []
            for trace in target_traces:
                route = tuple(hop['ip'] for hop in trace['hops'] if hop['ip'] != '*')
                if route:
                    routes.append(route)
            
            if not routes:
                continue
            
            # Count unique routes
            route_counter = Counter(routes)
            unique_routes = len(route_counter)
            most_common_route = route_counter.most_common(1)[0]
            
            # Calculate stability score (0-1, where 1 is perfectly stable)
            stability_score = most_common_route[1] / len(routes)
            
            # Find routers that appear in ALL routes (core infrastructure)
            if routes:
                all_ips = set(routes[0])
                for route in routes[1:]:
                    all_ips &= set(route)
                core_routers = list(all_ips)
            else:
                core_routers = []
            
            analysis[target] = {
                'target_name': target_name,
                'total_traces': len(target_traces),
                'unique_routes': unique_routes,
                'stability_score': stability_score,
                'most_common_route_count': most_common_route[1],
                'core_routers': core_routers,
                'route_changes': unique_routes - 1
            }
        
        return analysis
    
    def analyze_router_frequency(self) -> Dict:
        """Analyze how frequently each router appears across all traces"""
        traces = self.load_all_traces()
        
        if not traces:
            return {'error': 'No trace data available'}
        
        # Count router appearances
        router_counts = Counter()
        router_names = {}  # Map IP to hostname
        router_positions = defaultdict(list)  # Track hop positions
        total_traces = 0
        
        for trace in traces:
            if not trace['success']:
                continue
            
            total_traces += 1
            seen_in_trace = set()
            
            for hop in trace['hops']:
                if hop['ip'] != '*':
                    router_counts[hop['ip']] += 1
                    seen_in_trace.add(hop['ip'])
                    
                    # Store hostname
                    if hop['hostname'] != '*':
                        router_names[hop['ip']] = hop['hostname']
                    
                    # Track position
                    router_positions[hop['ip']].append(hop['hop'])
        
        # Build analysis
        router_analysis = []
        
        for ip, count in router_counts.most_common():
            frequency = count / total_traces if total_traces > 0 else 0
            positions = router_positions[ip]
            
            # Calculate criticality score
            # Critical routers: high frequency + consistent position
            position_variance = statistics.variance(positions) if len(positions) > 1 else 0
            criticality_score = frequency * (1 / (1 + position_variance))
            
            router_analysis.append({
                'ip': ip,
                'hostname': router_names.get(ip, 'unknown'),
                'appearances': count,
                'frequency': frequency,
                'avg_position': statistics.mean(positions),
                'position_variance': position_variance,
                'criticality_score': criticality_score
            })
        
        # Sort by criticality
        router_analysis.sort(key=lambda x: x['criticality_score'], reverse=True)
        
        return {
            'total_traces': total_traces,
            'unique_routers': len(router_counts),
            'routers': router_analysis
        }
    
    def analyze_time_patterns(self) -> Dict:
        """Analyze if routes change based on time of day"""
        traces = self.load_all_traces()
        
        if not traces:
            return {'error': 'No trace data available'}
        
        # Group by hour of day
        by_hour = defaultdict(list)
        
        for trace in traces:
            if not trace['success']:
                continue
            
            timestamp = datetime.fromisoformat(trace['timestamp'])
            hour = timestamp.hour
            
            route = tuple(hop['ip'] for hop in trace['hops'] if hop['ip'] != '*')
            by_hour[hour].append({
                'target': trace['target_ip'],
                'route': route,
                'timestamp': timestamp
            })
        
        # Analyze each hour
        hourly_analysis = {}
        
        for hour in range(24):
            if hour not in by_hour:
                continue
            
            hour_traces = by_hour[hour]
            
            # Count unique routes per target
            by_target = defaultdict(list)
            for trace in hour_traces:
                by_target[trace['target']].append(trace['route'])
            
            # Calculate average route diversity for this hour
            diversities = []
            for target_routes in by_target.values():
                unique = len(set(target_routes))
                total = len(target_routes)
                diversity = unique / total if total > 0 else 0
                diversities.append(diversity)
            
            avg_diversity = statistics.mean(diversities) if diversities else 0
            
            hourly_analysis[hour] = {
                'trace_count': len(hour_traces),
                'avg_route_diversity': avg_diversity,
                'targets_traced': len(by_target)
            }
        
        return hourly_analysis
    
    def generate_report(self, output_file='route_analysis_report.txt'):
        """Generate comprehensive analysis report"""
        print("\n" + "="*70)
        print("Generating Analysis Report")
        print("="*70 + "\n")
        
        traces = self.load_all_traces()
        
        if not traces:
            print("⚠ No trace data available. Run some trace cycles first.")
            return
        
        with open(output_file, 'w') as f:
            def write(text):
                print(text)
                f.write(text + '\n')
            
            write("="*70)
            write("TWAREN ROUTE MONITORING ANALYSIS REPORT")
            write("="*70)
            write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            write(f"Total traces analyzed: {len(traces)}")
            
            # Time range
            timestamps = [datetime.fromisoformat(t['timestamp']) for t in traces]
            write(f"Time range: {min(timestamps).strftime('%Y-%m-%d %H:%M')} to {max(timestamps).strftime('%Y-%m-%d %H:%M')}")
            duration = max(timestamps) - min(timestamps)
            write(f"Duration: {duration}")
            write("")
            
            # Route Stability Analysis
            write("\n" + "="*70)
            write("1. ROUTE STABILITY ANALYSIS")
            write("="*70 + "\n")
            
            stability = self.analyze_route_stability()
            
            # Sort by stability score
            sorted_targets = sorted(stability.items(), 
                                  key=lambda x: x[1].get('stability_score', 0))
            
            write("Most Unstable Routes (frequent changes):")
            for target, data in sorted_targets[:5]:
                write(f"\n  {data['target_name']} ({target})")
                write(f"    Stability Score: {data['stability_score']:.2%}")
                write(f"    Unique Routes: {data['unique_routes']}")
                write(f"    Total Traces: {data['total_traces']}")
                write(f"    Route Changes: {data['route_changes']}")
            
            write("\n" + "-"*70 + "\n")
            write("Most Stable Routes (consistent):")
            for target, data in sorted_targets[-5:]:
                write(f"\n  {data['target_name']} ({target})")
                write(f"    Stability Score: {data['stability_score']:.2%}")
                write(f"    Unique Routes: {data['unique_routes']}")
                write(f"    Core Routers: {len(data['core_routers'])}")
            
            # Router Frequency Analysis
            write("\n\n" + "="*70)
            write("2. CRITICAL INFRASTRUCTURE IDENTIFICATION")
            write("="*70 + "\n")
            
            router_freq = self.analyze_router_frequency()
            
            write(f"Total Unique Routers: {router_freq['unique_routers']}")
            write(f"Total Traces: {router_freq['total_traces']}\n")
            
            write("Top 20 Most Critical Routers (by criticality score):")
            write("  Criticality = Frequency × Position Consistency\n")
            
            for i, router in enumerate(router_freq['routers'][:20], 1):
                write(f"\n{i}. {router['hostname']}")
                write(f"   IP: {router['ip']}")
                write(f"   Appearances: {router['appearances']}/{router_freq['total_traces']} ({router['frequency']:.1%})")
                write(f"   Avg Position: {router['avg_position']:.1f}")
                write(f"   Criticality Score: {router['criticality_score']:.3f}")
            
            # Time Pattern Analysis
            write("\n\n" + "="*70)
            write("3. TIME-BASED ROUTING PATTERNS")
            write("="*70 + "\n")
            
            time_patterns = self.analyze_time_patterns()
            
            if 'error' not in time_patterns:
                write("Route Diversity by Hour of Day:")
                write("  (Higher diversity = more route changes)\n")
                
                for hour in sorted(time_patterns.keys()):
                    data = time_patterns[hour]
                    bar_length = int(data['avg_route_diversity'] * 50)
                    bar = '█' * bar_length
                    write(f"  {hour:02d}:00 [{data['trace_count']:3d} traces] {bar} {data['avg_route_diversity']:.2%}")
                
                # Find peak hours for route changes
                sorted_hours = sorted(time_patterns.items(), 
                                    key=lambda x: x[1]['avg_route_diversity'], 
                                    reverse=True)
                
                write(f"\n  Most variable routing hours:")
                for hour, data in sorted_hours[:3]:
                    write(f"    {hour:02d}:00 - Diversity: {data['avg_route_diversity']:.2%}")
                
                write(f"\n  Most stable routing hours:")
                for hour, data in sorted_hours[-3:]:
                    write(f"    {hour:02d}:00 - Diversity: {data['avg_route_diversity']:.2%}")
        
        print(f"\n✓ Report saved to {output_file}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='TWAREN Route Monitoring System')
    parser.add_argument('--mode', choices=['trace', 'analyze', 'continuous'], 
                       default='trace', help='Operation mode')
    parser.add_argument('--targets', default='twaren_targets.txt',
                       help='Target file')
    parser.add_argument('--interval', type=int, default=3600,
                       help='Interval between traces in seconds (for continuous mode)')
    parser.add_argument('--cycles', type=int, default=None,
                       help='Number of cycles to run (default: infinite)')
    
    args = parser.parse_args()
    
    monitor = RouteMonitor()
    
    if args.mode == 'trace':
        # Single trace cycle
        targets = monitor.load_targets(args.targets)
        if not targets:
            print("No targets found. Please create a target file first.")
            return
        monitor.run_trace_cycle(targets)
    
    elif args.mode == 'analyze':
        # Generate analysis report
        monitor.generate_report()
    
    elif args.mode == 'continuous':
        # Continuous monitoring
        targets = monitor.load_targets(args.targets)
        if not targets:
            print("No targets found. Please create a target file first.")
            return
        
        cycle_count = 0
        try:
            while args.cycles is None or cycle_count < args.cycles:
                monitor.run_trace_cycle(targets)
                cycle_count += 1
                
                if args.cycles is None or cycle_count < args.cycles:
                    next_run = datetime.now() + timedelta(seconds=args.interval)
                    print(f"\n⏰ Next cycle at {next_run.strftime('%H:%M:%S')}")
                    print(f"   Waiting {args.interval}s... (Ctrl+C to stop)\n")
                    time.sleep(args.interval)
        
        except KeyboardInterrupt:
            print("\n\n⚠ Monitoring stopped by user")
            print(f"✓ Completed {cycle_count} cycles")

if __name__ == '__main__':
    main()