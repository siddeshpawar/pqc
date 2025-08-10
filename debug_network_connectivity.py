#!/usr/bin/env python3
"""
Network Connectivity Diagnostic Script for PQC VPN
Helps debug connection issues between initiator and responder
"""

import socket
import subprocess
import sys
import time
import json
from typing import Dict, List, Tuple

class NetworkDiagnostic:
    def __init__(self):
        self.local_ip = None
        self.remote_ip = None
        self.port = 5001
        self.results = {}
        
    def get_local_ip(self) -> str:
        """Get the local IP address"""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception as e:
            print(f"[ERROR] Could not determine local IP: {e}")
            return None
    
    def check_interface_config(self) -> Dict:
        """Check network interface configuration"""
        print("\n[DIAG] Checking network interface configuration...")
        
        try:
            # Get IP configuration
            result = subprocess.run(['ip', 'addr', 'show'], 
                                  capture_output=True, text=True, timeout=10)
            interfaces = result.stdout
            
            # Get routing table
            route_result = subprocess.run(['ip', 'route'], 
                                        capture_output=True, text=True, timeout=10)
            routes = route_result.stdout
            
            print(f"[DIAG] Network interfaces:")
            for line in interfaces.split('\n'):
                if 'inet ' in line and '127.0.0.1' not in line:
                    print(f"  {line.strip()}")
            
            print(f"\n[DIAG] Routing table:")
            for line in routes.split('\n')[:5]:  # Show first 5 routes
                if line.strip():
                    print(f"  {line.strip()}")
                    
            return {
                "interfaces": interfaces,
                "routes": routes,
                "status": "success"
            }
            
        except Exception as e:
            print(f"[ERROR] Interface check failed: {e}")
            return {"status": "error", "error": str(e)}
    
    def check_port_availability(self, ip: str, port: int) -> Dict:
        """Check if a port is available for binding"""
        print(f"\n[DIAG] Checking port {port} availability on {ip}...")
        
        try:
            # Test UDP socket binding
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((ip, port))
                print(f"[DIAG] ✓ Port {port} is available on {ip}")
                return {"status": "available", "ip": ip, "port": port}
                
        except socket.error as e:
            print(f"[DIAG] ✗ Port {port} binding failed on {ip}: {e}")
            return {"status": "unavailable", "ip": ip, "port": port, "error": str(e)}
    
    def test_udp_connectivity(self, local_ip: str, remote_ip: str, port: int) -> Dict:
        """Test UDP connectivity between two IPs"""
        print(f"\n[DIAG] Testing UDP connectivity: {local_ip} → {remote_ip}:{port}")
        
        try:
            # Create UDP socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3.0)
                
                # Try to send a test message
                test_message = b"CONNECTIVITY_TEST"
                s.sendto(test_message, (remote_ip, port))
                print(f"[DIAG] ✓ Test message sent to {remote_ip}:{port}")
                
                return {"status": "sent", "message": "Test message sent successfully"}
                
        except socket.timeout:
            print(f"[DIAG] ⚠ Timeout sending to {remote_ip}:{port}")
            return {"status": "timeout", "error": "Connection timeout"}
        except socket.error as e:
            print(f"[DIAG] ✗ Socket error: {e}")
            return {"status": "error", "error": str(e)}
    
    def check_firewall_rules(self) -> Dict:
        """Check firewall configuration"""
        print(f"\n[DIAG] Checking firewall rules...")
        
        try:
            # Check iptables rules
            result = subprocess.run(['iptables', '-L', '-n'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                rules = result.stdout
                print(f"[DIAG] Firewall rules (first 10 lines):")
                for i, line in enumerate(rules.split('\n')[:10]):
                    if line.strip():
                        print(f"  {line}")
                
                # Check for common blocking rules
                if 'DROP' in rules or 'REJECT' in rules:
                    print(f"[DIAG] ⚠ Found DROP/REJECT rules - may block traffic")
                else:
                    print(f"[DIAG] ✓ No obvious blocking rules found")
                    
                return {"status": "checked", "rules": rules}
            else:
                print(f"[DIAG] ⚠ Could not check iptables (may need sudo)")
                return {"status": "permission_denied"}
                
        except Exception as e:
            print(f"[DIAG] ⚠ Firewall check failed: {e}")
            return {"status": "error", "error": str(e)}
    
    def ping_test(self, target_ip: str) -> Dict:
        """Test basic IP connectivity with ping"""
        print(f"\n[DIAG] Testing ping connectivity to {target_ip}...")
        
        try:
            result = subprocess.run(['ping', '-c', '3', target_ip], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                print(f"[DIAG] ✓ Ping to {target_ip} successful")
                return {"status": "success", "output": result.stdout}
            else:
                print(f"[DIAG] ✗ Ping to {target_ip} failed")
                return {"status": "failed", "output": result.stderr}
                
        except Exception as e:
            print(f"[DIAG] ✗ Ping test error: {e}")
            return {"status": "error", "error": str(e)}
    
    def run_full_diagnostic(self, local_ip: str = None, remote_ip: str = None):
        """Run complete network diagnostic"""
        print("=" * 60)
        print("PQC VPN Network Connectivity Diagnostic")
        print("=" * 60)
        
        # Determine IPs
        if not local_ip:
            local_ip = self.get_local_ip()
        if not local_ip:
            print("[ERROR] Could not determine local IP address")
            return
            
        print(f"[DIAG] Local IP: {local_ip}")
        if remote_ip:
            print(f"[DIAG] Remote IP: {remote_ip}")
        
        # Run diagnostic tests
        self.results['interface_config'] = self.check_interface_config()
        self.results['port_availability'] = self.check_port_availability(local_ip, self.port)
        self.results['firewall'] = self.check_firewall_rules()
        
        if remote_ip:
            self.results['ping_test'] = self.ping_test(remote_ip)
            self.results['udp_connectivity'] = self.test_udp_connectivity(local_ip, remote_ip, self.port)
        
        # Print summary
        print("\n" + "=" * 60)
        print("DIAGNOSTIC SUMMARY")
        print("=" * 60)
        
        print(f"✓ Interface configuration: {'OK' if self.results['interface_config']['status'] == 'success' else 'FAILED'}")
        print(f"✓ Port {self.port} availability: {'OK' if self.results['port_availability']['status'] == 'available' else 'FAILED'}")
        print(f"✓ Firewall check: {'OK' if self.results['firewall']['status'] == 'checked' else 'LIMITED'}")
        
        if remote_ip:
            print(f"✓ Ping to {remote_ip}: {'OK' if self.results['ping_test']['status'] == 'success' else 'FAILED'}")
            print(f"✓ UDP connectivity: {'OK' if self.results['udp_connectivity']['status'] == 'sent' else 'FAILED'}")
        
        # Recommendations
        print("\n" + "=" * 60)
        print("RECOMMENDATIONS")
        print("=" * 60)
        
        if self.results['port_availability']['status'] != 'available':
            print("• Port 5001 is not available - check if another process is using it")
            print("  Run: sudo netstat -tulpn | grep 5001")
        
        if remote_ip and self.results['ping_test']['status'] != 'success':
            print(f"• Basic ping to {remote_ip} failed - check network connectivity")
            print("  Verify IP addresses and network configuration")
        
        if 'DROP' in str(self.results.get('firewall', {})):
            print("• Firewall may be blocking traffic - check iptables rules")
            print("  Consider: sudo iptables -I INPUT -p udp --dport 5001 -j ACCEPT")
        
        print("\nFor VPN testing:")
        print("• Responder: python3 pqc_vpn_certificate_working.py <local_ip> <remote_ip> pqc_ipsec responder")
        print("• Initiator: python3 pqc_vpn_certificate_working.py <local_ip> <remote_ip> pqc_ipsec initiator")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 debug_network_connectivity.py <local_ip> [remote_ip]")
        print("Examples:")
        print("  python3 debug_network_connectivity.py 192.168.1.10")
        print("  python3 debug_network_connectivity.py 192.168.1.10 192.168.1.20")
        sys.exit(1)
    
    local_ip = sys.argv[1]
    remote_ip = sys.argv[2] if len(sys.argv) > 2 else None
    
    diagnostic = NetworkDiagnostic()
    diagnostic.run_full_diagnostic(local_ip, remote_ip)

if __name__ == "__main__":
    main()
