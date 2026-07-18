#!/usr/bin/env python
"""Test basic connectivity."""
import subprocess
import socket

print("Testing basic network connectivity...")
print("\n1. Testing ipconfig output:")
result = subprocess.run(['ipconfig'], capture_output=True, text=True)
if 'IPv4 Address' in result.stdout:
    print("✓ System has IPv4 connectivity")
    # Extract IP and gateway
    for line in result.stdout.split('\n'):
        if 'IPv4 Address' in line or 'Default Gateway' in line or 'Subnet Mask' in line:
            print(f"  {line.strip()}")

print("\n2. Testing ping to gateway:")
result = subprocess.run(['ping', '-n', '1', '10.75.73.139'], capture_output=True, text=True)
if 'Reply from' in result.stdout:
    print("✓ Gateway is reachable via ping")
    print(result.stdout.split('\n')[1])
else:
    print("✗ Gateway ping failed")

print("\n3. Testing broadcast with longer timeout:")
try:
    result = subprocess.run(['ping', '-n', '1', '-w', '2000', '10.75.73.255'], 
                          capture_output=True, text=True, timeout=5)
    if 'Reply from' in result.stdout:
        print("✓ Broadcast address got responses")
    else:
        print("⊘ Broadcast ping had no responses (expected)")
except subprocess.TimeoutExpired:
    print("⊘ Broadcast ping timeout (expected for broadcast)")

print("\n4. Checking arp -a output:")
result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
lines = result.stdout.split('\n')
arp_entries = [l for l in lines if '10.75' in l and 'dynamic' in l.lower()]
print(f"Found {len(arp_entries)} ARP entries for 10.75 network")
for entry in arp_entries[:5]:
    print(f"  {entry.strip()}")
if len(arp_entries) > 5:
    print(f"  ... and {len(arp_entries) - 5} more")

print("\n5. Testing Scapy with simple gateway ARP:")
from scapy.all import ARP, Ether, srp, get_if_list

iface = get_if_list()[0]
print(f"Using interface: {iface}")

# Test just the gateway first
gateway_ip = "10.75.73.139"
print(f"Attempting ARP request to gateway {gateway_ip}...")
try:
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
    answered, _ = srp(packet, timeout=1, retry=0, iface=iface, verbose=False)
    print(f"Responses: {len(answered)}")
    for _, received in answered:
        print(f"  {received.psrc} -> {received.hwsrc}")
except Exception as e:
    print(f"Error: {e}")
