#!/usr/bin/env python
"""Test network scanning with fallback methods."""
from app import read_arp_table, ping_network, get_local_interfaces, run_network_scan
from ipaddress import IPv4Network

print("=" * 60)
print("ARP TABLE TEST (Fallback Method)")
print("=" * 60)
arp_table = read_arp_table()
print(f"Found {len(arp_table)} devices in ARP table:")
for ip, mac in arp_table.items():
    print(f"  {ip:15} -> {mac}")

print("\n" + "=" * 60)
print("PING NETWORK TEST")
print("=" * 60)
interfaces = get_local_interfaces()
if interfaces:
    network = interfaces[0]["scan_network"]
    print(f"Pinging network: {network}")
    results = ping_network(network)
    print(f"Ping responses: {len(results)} hosts responded")
    for ip, latency in list(results.items())[:5]:
        print(f"  {ip:15} -> {latency}ms")
    if len(results) > 5:
        print(f"  ... and {len(results) - 5} more")

print("\n" + "=" * 60)
print("FULL NETWORK SCAN TEST")
print("=" * 60)
result = run_network_scan()
print(f"Scan Result:")
print(f"  Status: {'SUCCESS' if result['ok'] else 'FAILED'}")
if 'message' in result:
    print(f"  Message: {result['message']}")
print(f"  Devices Found: {result.get('devicesFound', 0)}")
print(f"  ARP Devices Found: {result.get('arpDevicesFound', 0)}")
print(f"  Scapy Enabled: {result.get('scapyEnabled', False)}")
if result.get('scapyError'):
    print(f"  Scapy Error: {result['scapyError']}")
