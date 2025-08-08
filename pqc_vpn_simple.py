#!/usr/bin/env python3
"""
Simplified PQC VPN Gateway Implementation
Uses only built-in Python libraries - No external dependencies
"""

import os
import socket
import struct
import threading
import time
import json
import hashlib
import hmac
from datetime import datetime
from typing import Dict, Optional, Tuple
import subprocess

class SimplePQCCrypto:
    """Simplified PQC crypto using built-in libraries"""
    
    def __init__(self):
        self.private_key = os.urandom(32)  # 256-bit private key
        self.public_key = hashlib.sha256(self.private_key).digest()  # Derive public key
        
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate simple key pair"""
        return self.public_key, self.private_key
    
    def sign(self, message: bytes) -> bytes:
        """Simple signature using HMAC (simulates ML-DSA)"""
        return hmac.new(self.private_key, message, hashlib.sha256).digest()
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify simple signature"""
        # Derive private key from public key (simplified for demo)
        derived_private = hashlib.sha256(public_key + b"private").digest()
        expected_sig = hmac.new(derived_private, message, hashlib.sha256).digest()
        return hmac.compare_digest(signature, expected_sig)

class SimpleTunnelInterface:
    """Simplified tunnel interface management"""
    
    def __init__(self, interface_name="pqc-vpn", local_ip="10.0.0.1"):
        self.interface_name = interface_name
        self.local_ip = local_ip
        
    def create_tunnel(self):
        """Create TUN interface"""
        try:
            # Create TUN interface
            subprocess.run([
                "sudo", "ip", "tuntap", "add", "dev", self.interface_name, "mode", "tun"
            ], check=True)
            
            # Configure IP
            subprocess.run([
                "sudo", "ip", "addr", "add", f"{self.local_ip}/30", "dev", self.interface_name
            ], check=True)
            
            # Bring up
            subprocess.run([
                "sudo", "ip", "link", "set", "dev", self.interface_name, "up"
            ], check=True)
            
            print(f"[TUNNEL] Created {self.interface_name} with IP {self.local_ip}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to create tunnel: {e}")
            return False
    
    def destroy_tunnel(self):
        """Destroy TUN interface"""
        try:
            subprocess.run(["sudo", "ip", "link", "delete", self.interface_name], check=True)
            print(f"[TUNNEL] Destroyed {self.interface_name}")
        except subprocess.CalledProcessError:
            pass

class SimpleESPProcessor:
    """Simplified ESP encryption using built-in crypto"""
    
    def __init__(self, key: bytes):
        self.key = key
        self.sequence = 0
        
    def encrypt_packet(self, payload: bytes) -> bytes:
        """Simple encryption using XOR (for demo purposes)"""
        self.sequence += 1
        
        # Create key stream from sequence and key
        key_stream = hashlib.sha256(self.key + struct.pack(">I", self.sequence)).digest()
        
        # XOR encryption
        encrypted = bytes(a ^ b for a, b in zip(payload, key_stream * ((len(payload) // 32) + 1)))
        
        # Add sequence number
        return struct.pack(">I", self.sequence) + encrypted
    
    def decrypt_packet(self, packet: bytes) -> Optional[bytes]:
        """Simple decryption"""
        if len(packet) < 4:
            return None
            
        sequence = struct.unpack(">I", packet[:4])[0]
        encrypted = packet[4:]
        
        # Recreate key stream
        key_stream = hashlib.sha256(self.key + struct.pack(">I", sequence)).digest()
        
        # XOR decryption
        decrypted = bytes(a ^ b for a, b in zip(encrypted, key_stream * ((len(encrypted) // 32) + 1)))
        
        return decrypted

class SimplePQCVPNGateway:
    """Simplified PQC VPN Gateway"""
    
    def __init__(self, local_ip: str, remote_ip: str, is_initiator: bool = True):
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.is_initiator = is_initiator
        
        # Crypto
        self.crypto = SimplePQCCrypto()
        self.public_key, self.private_key = self.crypto.generate_keypair()
        self.shared_secret = None
        self.esp_processor = None
        
        # Network
        self.tunnel = None
        self.udp_socket = None
        
        # State
        self.ike_established = False
        self.tunnel_established = False
        
        print(f"[INIT] Simple PQC VPN Gateway")
        print(f"[INIT] Role: {'Initiator' if is_initiator else 'Responder'}")
        print(f"[INIT] Local: {local_ip}, Remote: {remote_ip}")
        print(f"[INIT] Using built-in crypto (no external dependencies)")
    
    def start(self):
        """Start VPN gateway"""
        print("[START] Starting VPN gateway...")
        
        # Create UDP socket (use port 5000 instead of 500 to avoid privilege issues)
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.udp_socket.bind((self.local_ip, 500))
        except OSError as e:
            print(f"[WARNING] Cannot bind to port 500: {e}")
            print("[INFO] Trying port 5000 instead...")
            self.udp_socket.bind((self.local_ip, 5000))
        self.udp_socket.settimeout(5.0)
        
        if self.is_initiator:
            self._initiate_handshake()
        else:
            self._respond_handshake()
    
    def _initiate_handshake(self):
        """Initiate handshake"""
        print("[IKE] Initiating handshake...")
        
        # Send initial message
        message = {
            "type": "INIT",
            "public_key": self.public_key.hex(),
            "timestamp": int(time.time())
        }
        
        self._send_message(message)
        self._listen_for_messages()
    
    def _respond_handshake(self):
        """Respond to handshake"""
        print("[IKE] Waiting for handshake...")
        self._listen_for_messages()
    
    def _send_message(self, message: Dict):
        """Send message"""
        data = json.dumps(message).encode()
        # Use same port as we're listening on (500 or 5000)
        local_port = self.udp_socket.getsockname()[1]
        self.udp_socket.sendto(data, (self.remote_ip, local_port))
    
    def _listen_for_messages(self):
        """Listen for messages"""
        retry_count = 0
        max_retries = 20
        
        while not self.ike_established and retry_count < max_retries:
            try:
                data, addr = self.udp_socket.recvfrom(4096)
                message = json.loads(data.decode())
                self._handle_message(message, addr)
            except socket.timeout:
                retry_count += 1
                if self.is_initiator and retry_count % 5 == 0:
                    print(f"[IKE] Retrying... ({retry_count}/{max_retries})")
                continue
            except Exception as e:
                print(f"[ERROR] Message handling error: {e}")
                retry_count += 1
    
    def _handle_message(self, message: Dict, addr: Tuple[str, int]):
        """Handle received message"""
        msg_type = message.get("type")
        print(f"[IKE] Received {msg_type} from {addr[0]}")
        
        if msg_type == "INIT":
            self._handle_init(message, addr)
        elif msg_type == "RESPONSE":
            self._handle_response(message, addr)
        elif msg_type == "AUTH":
            self._handle_auth(message, addr)
    
    def _handle_init(self, message: Dict, addr: Tuple[str, int]):
        """Handle INIT message"""
        peer_public_key = bytes.fromhex(message["public_key"])
        
        # Generate shared secret
        self.shared_secret = hashlib.sha256(self.private_key + peer_public_key).digest()
        self.esp_processor = SimpleESPProcessor(self.shared_secret)
        
        # Send response
        response = {
            "type": "RESPONSE",
            "public_key": self.public_key.hex(),
            "timestamp": int(time.time())
        }
        self._send_message(response)
        
        # Send auth
        self._send_auth()
    
    def _handle_response(self, message: Dict, addr: Tuple[str, int]):
        """Handle RESPONSE message"""
        peer_public_key = bytes.fromhex(message["public_key"])
        
        # Generate shared secret
        self.shared_secret = hashlib.sha256(self.private_key + peer_public_key).digest()
        self.esp_processor = SimpleESPProcessor(self.shared_secret)
        
        # Send auth
        self._send_auth()
    
    def _send_auth(self):
        """Send authentication"""
        auth_data = f"AUTH:{self.local_ip}:{int(time.time())}"
        signature = self.crypto.sign(auth_data.encode())
        
        auth_message = {
            "type": "AUTH",
            "auth_data": auth_data,
            "signature": signature.hex(),
            "public_key": self.public_key.hex()
        }
        
        self._send_message(auth_message)
        print("[IKE] Sent authentication with PQC signature")
    
    def _handle_auth(self, message: Dict, addr: Tuple[str, int]):
        """Handle AUTH message"""
        auth_data = message["auth_data"].encode()
        signature = bytes.fromhex(message["signature"])
        peer_public_key = bytes.fromhex(message["public_key"])
        
        if self.crypto.verify(auth_data, signature, peer_public_key):
            print("[IKE] PQC signature verification SUCCESS")
            self.ike_established = True
            self._establish_tunnel()
        else:
            print("[IKE] PQC signature verification FAILED")
    
    def _establish_tunnel(self):
        """Establish tunnel"""
        print("[TUNNEL] Establishing tunnel...")
        
        tunnel_ip = "10.100.0.1" if self.is_initiator else "10.100.0.2"
        interface_name = f"pqc-vpn-{self.local_ip.replace('.', '-')}"
        
        self.tunnel = SimpleTunnelInterface(interface_name, tunnel_ip)
        
        if self.tunnel.create_tunnel():
            self.tunnel_established = True
            print("[TUNNEL] Tunnel established successfully")
            self._setup_routing()
            print("[VPN] Simple PQC VPN is ACTIVE!")
        else:
            print("[TUNNEL] Failed to establish tunnel")
    
    def _setup_routing(self):
        """Setup routing"""
        try:
            if self.is_initiator:
                subprocess.run([
                    "sudo", "ip", "route", "add", "10.2.2.0/24", "dev", self.tunnel.interface_name
                ], check=True)
            else:
                subprocess.run([
                    "sudo", "ip", "route", "add", "10.1.1.0/24", "dev", self.tunnel.interface_name
                ], check=True)
            print("[ROUTING] Routes configured")
        except subprocess.CalledProcessError as e:
            print(f"[ROUTING] Route setup failed: {e}")
    
    def get_status(self) -> Dict:
        """Get status"""
        return {
            "ike_established": self.ike_established,
            "tunnel_established": self.tunnel_established,
            "local_ip": self.local_ip,
            "remote_ip": self.remote_ip,
            "role": "initiator" if self.is_initiator else "responder",
            "tunnel_interface": self.tunnel.interface_name if self.tunnel else None,
            "tunnel_ip": self.tunnel.local_ip if self.tunnel else None
        }
    
    def shutdown(self):
        """Shutdown"""
        print("[SHUTDOWN] Shutting down...")
        
        self.ike_established = False
        self.tunnel_established = False
        
        if self.tunnel:
            self.tunnel.destroy_tunnel()
        
        if self.udp_socket:
            self.udp_socket.close()

def main():
    """Main function"""
    import sys
    
    if len(sys.argv) != 4:
        print("Usage: python3 pqc_vpn_simple.py <local_ip> <remote_ip> <initiator|responder>")
        print("")
        print("Examples:")
        print("  VM1: python3 pqc_vpn_simple.py 192.168.1.10 192.168.1.20 initiator")
        print("  VM2: python3 pqc_vpn_simple.py 192.168.1.20 192.168.1.10 responder")
        sys.exit(1)
    
    local_ip = sys.argv[1]
    remote_ip = sys.argv[2]
    is_initiator = sys.argv[3].lower() == "initiator"
    
    gateway = SimplePQCVPNGateway(local_ip, remote_ip, is_initiator)
    
    try:
        gateway.start()
        
        while True:
            status = gateway.get_status()
            print(f"[STATUS] IKE: {status['ike_established']}, Tunnel: {status['tunnel_established']}")
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
        gateway.shutdown()

if __name__ == "__main__":
    main()
