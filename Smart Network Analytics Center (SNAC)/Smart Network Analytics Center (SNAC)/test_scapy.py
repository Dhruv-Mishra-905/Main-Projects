#!/usr/bin/env python
"""Test Scapy ARP scanning capability."""
from app import (
    SCAPY_AVAILABLE,
    SCAPY_ERROR,
    get_local_interfaces,
    get_scapy_interface,
    arp_scan_network,
)

print("=" * 60)
print("SCAPY AVAILABILITY TEST")
print("=" * 60)
print(f"Scapy Available: {SCAPY_AVAILABLE}")
if SCAPY_ERROR:
    print(f"Scapy Error: {SCAPY_ERROR}")

print("\n" + "=" * 60)
print("LOCAL INTERFACES TEST")
print("=" * 60)
interfaces = get_local_interfaces()
if not interfaces:
    print("No local interfaces detected!")
else:
    for i, iface in enumerate(interfaces):
        print(f"\nInterface {i + 1}:")
        print(f"  IP Address: {iface['ip_address']}")
        print(f"  Full Network: {iface['full_network']}")
        print(f"  Scan Network: {iface['scan_network']}")

print("\n" + "=" * 60)
print("SCAPY INTERFACE MAPPING TEST")
print("=" * 60)
for i, iface in enumerate(interfaces):
    scapy_iface = get_scapy_interface(iface["scan_network"])
    print(f"Interface {i + 1} ({iface['scan_network']}) -> Scapy: {scapy_iface}")

print("\n" + "=" * 60)
print("ARP SCAN TEST (Small subnet)")
print("=" * 60)
if interfaces:
    network = interfaces[0]["scan_network"]
    print(f"Scanning network: {network}")
    print("Starting ARP scan...")
    results = arp_scan_network(network)
    print(f"Devices found: {len(results)}")
    for ip, mac in list(results.items())[:5]:
        print(f"  {ip} -> {mac}")
    if len(results) > 5:
        print(f"  ... and {len(results) - 5} more")
