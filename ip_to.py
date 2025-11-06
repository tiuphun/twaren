import re

# Your input data (paste all your content here)
data = """
# TWAREN Target IPs for Network Mapping
# Generated: 2025-10-12T17:06:11.451030
# Source: CCU

120.101.5.5	# NIU - core.niu.edu.tw
134.208.9.114	# NDHU - twaren.ndhu.edu.tw
140.109.13.33	# SINICA - rt.sinica.edu.tw
140.112.0.201	# NTU - core_wan_0201.cc.ntu.edu.tw
140.112.0.69	# NTU - wan0069.cc.ntu.edu.tw
140.114.1.69	# NTHU - c7609c-c6509.nthu.edu.tw
140.116.229.1	# NCKU - ncku.edu.tw
140.119.166.199	# NCCU - nccu.edu.tw
140.123.1.2	# CCU - suncc.ccu.edu.tw
140.123.103.250	# NTU - csgate103.cs.ccu.edu.tw
211.73.76.114	# NIU - niu-a1.twaren.net
211.73.76.141	# NCU - hc-a2.twaren.net
211.73.76.150	# NCU - ncu-a1.twaren.net
211.73.76.154	# NYCU - nctu-a1.twaren.net
211.73.76.194	# NCNU - ncnu-a1.twaren.net
211.73.76.198	# NCU - tn-a2.twaren.net
211.73.76.209	# NDHU - tp-a1.twaren.net
211.73.76.214	# NCKU - ncku-a1.twaren.net
211.73.76.218	# NSYSU - nsysu-a1.twaren.net
211.73.76.66	# NIU - tp-a2.twaren.net
211.73.76.81	# NDHU - tp-a1.twaren.net
211.73.76.90	# NDHU - ndhu-a1.twaren.net
211.79.50.146	# NIU - niu_niu-a1.twaren.net
211.79.51.26	# NCU - ncu-76-ncu.twaren.net
211.79.53.30	# NYCU - nctu-76-nctu.twaren.net
211.79.55.38	# NCNU - ncnu-76-ncnu-2.twaren.net
211.79.56.26	# NCKU - ncku-76-ncku.twaren.net
211.79.57.25	# NDHU - ccu-ccu-76.twaren.net
211.79.58.26	# NSYSU - nsysu_nsysu-a1.twaren.net

# Alternative TWAREN Targets
# Use these IPs for traceroute when direct domain traces fail


# NTU (ntu.edu.tw)
140.112.2.165 # webmail.ntu.edu.tw
140.112.36.185 # ftp.ntu.edu.tw
140.112.2.2 # ntu3.ntu.edu.tw

# NDHU (ndhu.edu.tw)
134.208.14.219 # www.ndhu.edu.tw
142.251.170.26 # ASPMX.L.GOOGLE.COM
172.217.78.26 # ALT1.ASPMX.L.GOOGLE.COM

# NCU (ncu.edu.tw)
140.115.17.128 # smtp.ncu.edu.tw
140.115.154.112 # ee.ncu.edu.tw
140.115.17.111 # pop.ncu.edu.tw

# NTHU (nthu.edu.tw)
140.114.63.93 # antispam.net.nthu.edu.tw
140.114.63.20 # dns3.nthu.edu.tw
140.114.67.68 # ee.nthu.edu.tw

# NYCU (nycu.edu.tw)
140.113.39.18 # lib.nycu.edu.tw
140.113.0.45 # vpn.nycu.edu.tw
172.217.78.26 # ALT1.ASPMX.L.GOOGLE.COM

# NCHU (nchu.edu.tw)
140.120.1.21 # pds.nchu.edu.tw
140.120.152.8 # sqr.nchu.edu.tw
140.120.1.2 # nchud1.nchu.edu.tw

# NCNU (ncnu.edu.tw)
163.22.2.38 # webmail.ncnu.edu.tw
163.22.2.38 # pop.ncnu.edu.tw
163.22.16.130 # moodle.ncnu.edu.tw

# CCU (ccu.edu.tw)
140.123.13.215 # ee.ccu.edu.tw
140.123.135.249 # vpn.ccu.edu.tw
140.123.13.215 # lib.ccu.edu.tw

# NCKU (ncku.edu.tw)
163.28.112.1 # name.ncku.edu.tw
140.116.241.66 # lib.ncku.edu.tw
140.116.49.101 # ee.ncku.edu.tw

# NSYSU (nsysu.edu.tw)
140.117.166.10 # ee.nsysu.edu.tw
140.117.111.1 # vpn.nsysu.edu.tw
140.117.11.50 # mail.nsysu.edu.tw

# NIU (niu.edu.tw)
120.101.0.3 # imap.niu.edu.tw
120.101.0.37 # lib.niu.edu.tw
203.145.203.101 # cs.niu.edu.tw

# NCCU (nccu.edu.tw)
140.119.34.23 # moodle.nccu.edu.tw
140.119.166.199 # nccu.edu.tw
140.119.226.191 # vpn.nccu.edu.tw

# Alternative TWAREN Targets
# Use these IPs for traceroute when direct domain traces fail


# NTU (ntu.edu.tw)
140.112.36.185 # ftp.ntu.edu.tw
140.112.8.116 # www.ntu.edu.tw
140.112.2.165 # webmail.ntu.edu.tw

# NDHU (ndhu.edu.tw)
134.208.14.219 # www.ndhu.edu.tw
134.208.14.219 # ee.ndhu.edu.tw
134.208.14.111 # webmail.ndhu.edu.tw

# NCU (ncu.edu.tw)
140.115.154.112 # ee.ncu.edu.tw
140.115.1.29 # dns.ncu.edu.tw
140.115.130.211 # lib.ncu.edu.tw

# NTHU (nthu.edu.tw)
211.79.61.47 # dns3.twaren.net
140.114.69.134 # moodle.nthu.edu.tw
140.114.63.20 # dns3.nthu.edu.tw

# NYCU (nycu.edu.tw)
140.113.250.136 # ns2.nycu.edu.tw
140.113.41.157 # portal.nycu.edu.tw
140.113.39.18 # lib.nycu.edu.tw

# NCHU (nchu.edu.tw)
140.120.3.160 # portal.nchu.edu.tw
140.120.152.9 # sqr2.nchu.edu.tw
140.120.1.20 # www.nchu.edu.tw

# NCNU (ncnu.edu.tw)
211.79.61.47 # dns3.twaren.net
163.22.2.38 # imap.ncnu.edu.tw
163.22.2.2 # taurus.ncnu.edu.tw

# CCU (ccu.edu.tw)
140.123.13.215 # lib.ccu.edu.tw
140.123.2.25 # webmail.ccu.edu.tw
140.123.254.17 # dns2.ccu.edu.tw

# NCKU (ncku.edu.tw)
163.28.113.1 # apple.ncku.edu.tw
163.28.112.1 # name.ncku.edu.tw
140.116.249.68 # moodle.ncku.edu.tw

# NSYSU (nsysu.edu.tw)
140.117.11.26 # elearn.nsysu.edu.tw
140.117.11.50 # mail.nsysu.edu.tw
140.117.111.1 # vpn.nsysu.edu.tw

# NIU (niu.edu.tw)
120.101.0.3 # mail.niu.edu.tw
120.101.0.37 # lib.niu.edu.tw
120.101.0.9 # ns1.niu.edu.tw

# NCCU (nccu.edu.tw)
140.119.168.10 # www.nccu.edu.tw
140.119.216.47 # ftp.nccu.edu.tw
140.119.34.235 # elearn.nccu.edu.tw


# TWAREN Target IPs for Network Mapping
# Generated: 2025-10-12T16:15:30.269526
# Source: CCU

120.101.5.5	# NIU - core.niu.edu.tw
134.208.9.114	# NDHU - twaren.ndhu.edu.tw
140.109.13.33	# SINICA - rt.sinica.edu.tw
211.73.76.209	# NCKU - tp-a1.twaren.net
211.73.76.214	# NCKU - ncku-a1.twaren.net
211.79.56.26	# NCKU - ncku-76-ncku.twaren.net
211.79.57.25	# NCKU - ccu-ccu-76.twaren.net

# TWAREN Target IPs for Network Mapping
# Generated: 2025-10-12T17:42:36.898643
# Source: CCU

120.101.5.5	# NIU - core.niu.edu.tw
134.208.9.114	# NDHU - twaren.ndhu.edu.tw
140.109.13.33	# SINICA - rt.sinica.edu.tw
140.112.0.201	# NTU - core_wan_0201.cc.ntu.edu.tw
140.112.0.69	# NTU - wan0069.cc.ntu.edu.tw
140.114.1.69	# NTHU - c7609c-c6509.nthu.edu.tw
140.116.229.1	# NCKU - ncku.edu.tw
140.119.166.199	# NCCU - nccu.edu.tw
140.123.1.2	# CCU - suncc.ccu.edu.tw
140.123.103.250	# NTU - csgate103.cs.ccu.edu.tw
211.73.76.114	# NIU - niu-a1.twaren.net
211.73.76.141	# NCU - hc-a2.twaren.net
211.73.76.150	# NCU - ncu-a1.twaren.net
211.73.76.154	# NYCU - nctu-a1.twaren.net
211.73.76.194	# NCNU - ncnu-a1.twaren.net
211.73.76.198	# NCU - tn-a2.twaren.net
211.73.76.209	# NDHU - tn-a1.twaren.net
211.73.76.214	# NCKU - ncku-a1.twaren.net
211.73.76.218	# NSYSU - nsysu-a1.twaren.net
211.73.76.66	# NIU - tp-a2.twaren.net
211.73.76.81	# NDHU - tp-a1.twaren.net
211.73.76.90	# NDHU - ndhu-a1.twaren.net
211.79.50.146	# NIU - niu_niu-a1.twaren.net
211.79.51.26	# NCU - ncu-76-ncu.twaren.net
211.79.53.30	# NYCU - nctu-76-nctu.twaren.net
211.79.55.38	# NCNU - ncnu-76-ncnu-2.twaren.net
211.79.56.26	# NCKU - ncku-76-ncku.twaren.net
211.79.57.25	# NDHU - ccu-ccu-76.twaren.net
211.79.58.26	# NSYSU - nsysu_nsysu-a1.twaren.net

"""

# Dictionary to store IP -> router names mapping
ip_to_routers = {}

# Pattern to match lines with IP and comment
line_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+#\s*(.+)$'

# Process each line
for line in data.split('\n'):
    match = re.match(line_pattern, line.strip())
    if match:
        ip = match.group(1)
        router_name = match.group(2).strip()
        
        # Add router name to the set for this IP (to handle duplicates)
        if ip not in ip_to_routers:
            ip_to_routers[ip] = []
        if router_name not in ip_to_routers[ip]:
            ip_to_routers[ip].append(router_name)

# Sort IPs
sorted_ips = sorted(ip_to_routers.keys(), key=lambda ip: tuple(map(int, ip.split('.'))))

# Print results
print(f"Found {len(sorted_ips)} unique IP addresses\n")
print("=" * 80)

for ip in sorted_ips:
    routers = " | ".join(ip_to_routers[ip])
    print(f"{ip:15} # {routers}")

print("=" * 80)
print(f"\nTotal unique IPs: {len(sorted_ips)}")

# Optional: Save to file
with open('my_targets.txt', 'w') as f:
     for ip in sorted_ips:
         routers = " | ".join(ip_to_routers[ip])
         f.write(f"{ip:15} # {routers}\\n")
# print("\n" + "=" * 80)
# print("To save to file, uncomment the following lines:")
# print("=" * 80)
# print("""
#  with open('my_targets.txt', 'w') as f:
#      for ip in sorted_ips:
#          routers = " | ".join(ip_to_routers[ip])
#          f.write(f"{ip:15} # {routers}\\n")
# """)