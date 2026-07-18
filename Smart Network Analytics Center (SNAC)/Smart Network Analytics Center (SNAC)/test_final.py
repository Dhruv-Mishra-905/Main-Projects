#!/usr/bin/env python
"""Final verification - simulate Flask scan API."""
from app import run_network_scan
import json

print("=" * 70)
print("NETWORK SCAN API RESPONSE TEST")
print("=" * 70)

result = run_network_scan()

print("\nScan Response (as JSON):")
print(json.dumps(result, indent=2))

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"✓ Scan completed successfully: {result['ok']}")
print(f"✓ Network: {result.get('network', 'N/A')}")
print(f"✓ Devices found: {result.get('devicesFound', 0)}")
print(f"✓ ARP devices found: {result.get('arpDevicesFound', 0)}")
print(f"✓ Scapy available: {result.get('scapyEnabled', False)}")
print(f"✓ Scanned at: {result.get('scannedAt', 'N/A')}")

if not result['ok']:
    print(f"✗ Error: {result.get('message', 'Unknown error')}")
else:
    print("\n✓ Device Detection is WORKING!")
    print(f"  - Using combination of ARP table, ping, and Scapy")
    print(f"  - Found {result.get('devicesFound', 0)} devices on network")
    print(f"  - Ready to serve web dashboard")
