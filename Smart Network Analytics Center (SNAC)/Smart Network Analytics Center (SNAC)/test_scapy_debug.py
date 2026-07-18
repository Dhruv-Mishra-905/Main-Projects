#!/usr/bin/env python
"""Debug Scapy ARP scanning."""
import logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

from scapy.all import ARP, Ether, srp, get_if_list, conf

print("Testing Scapy ARP scan with detailed output...")
print(f"Available interfaces: {get_if_list()}")
print(f"Scapy verbose level: {conf.verb}")

# Test with verbose output
network = "10.75.73.0/24"
iface = get_if_list()[0]

print(f"\nAttempting ARP scan on network {network} using interface {iface}")
print("Creating ARP packet...")

try:
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    print(f"Packet created: {packet}")
    
    print(f"Sending packet with srp() (timeout=2s)...")
    conf.verb = 1  # Enable verbose output
    answered, unanswered = srp(packet, timeout=2, retry=1, iface=iface, verbose=False)
    conf.verb = 0  # Disable verbose output
    
    print(f"\nAnswered: {len(answered)} responses")
    print(f"Unanswered: {len(unanswered)} packets")
    
    for _, received in answered:
        print(f"  Response: {received.psrc} -> {received.hwsrc}")
        
except Exception as e:
    import traceback
    print(f"ERROR: {e}")
    traceback.print_exc()

print("\nTesting with alternative approach...")
try:
    # Try without verbose mode first to see if that helps
    print("Creating fresh packet...")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    
    print("Calling srp with verbose=False...")
    answered, unanswered = srp(packet, timeout=2, retry=0, iface=iface, verbose=False)
    
    print(f"Results: {len(answered)} answered")
    for _, received in answered:
        print(f"  {received.psrc} -> {received.hwsrc}")
        
except Exception as e:
    import traceback
    print(f"ERROR: {e}")
    traceback.print_exc()
