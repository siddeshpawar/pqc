#!/usr/bin/env python3
"""
Network connectivity test for ML-DSA VPN
Tests UDP communication between initiator and responder
"""

import socket
import sys
import time
import threading
import json

def test_udp_server(local_ip, port):
    """Test UDP server - listens for messages"""
    print(f"[SERVER] Starting UDP server on {local_ip}:{port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((local_ip, port))
        sock.settimeout(30)  # 30 second timeout
        
        print(f"[SERVER] ✅ Successfully bound to {local_ip}:{port}")
        print(f"[SERVER] Listening for messages...")
        
        while True:
            try:
                data, addr = sock.recvfrom(8192)
                print(f"[SERVER] ✅ Received {len(data)} bytes from {addr}")
                print(f"[SERVER] Data preview: {data[:100]}...")
                
                # Send response
                response = json.dumps({"status": "received", "size": len(data)}).encode()
                sock.sendto(response, addr)
                print(f"[SERVER] ✅ Sent response to {addr}")
                
            except socket.timeout:
                print(f"[SERVER] ⏰ No messages received in 30 seconds")
                break
            except Exception as e:
                print(f"[SERVER] ❌ Error: {e}")
                break
                
    except Exception as e:
        print(f"[SERVER] ❌ Failed to start server: {e}")
    finally:
        sock.close()

def test_udp_client(local_ip, remote_ip, remote_port):
    """Test UDP client - sends messages"""
    print(f"[CLIENT] Testing connection from {local_ip} to {remote_ip}:{remote_port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((local_ip, 0))  # Bind to any available port
        sock.settimeout(10)  # 10 second timeout
        
        local_port = sock.getsockname()[1]
        print(f"[CLIENT] ✅ Bound to local port {local_port}")
        
        # Send test message
        test_message = json.dumps({
            "type": "network_test",
            "from": f"{local_ip}:{local_port}",
            "timestamp": time.time(),
            "message": "Hello from network test!"
        }).encode()
        
        print(f"[CLIENT] Sending test message ({len(test_message)} bytes)...")
        sock.sendto(test_message, (remote_ip, remote_port))
        print(f"[CLIENT] ✅ Message sent to {remote_ip}:{remote_port}")
        
        # Wait for response
        print(f"[CLIENT] Waiting for response...")
        try:
            data, addr = sock.recvfrom(8192)
            print(f"[CLIENT] ✅ Received response from {addr}: {data.decode()}")
            return True
        except socket.timeout:
            print(f"[CLIENT] ❌ No response received (timeout)")
            return False
            
    except Exception as e:
        print(f"[CLIENT] ❌ Client test failed: {e}")
        return False
    finally:
        sock.close()

def check_firewall_ports():
    """Check if required ports are available"""
    print(f"[FIREWALL] Checking port availability...")
    
    ports_to_check = [5001, 5002]
    
    for port in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', port))
            sock.close()
            print(f"[FIREWALL] ✅ Port {port} is available")
        except Exception as e:
            print(f"[FIREWALL] ❌ Port {port} is not available: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Server mode: python3 network_test.py server <local_ip>")
        print("  Client mode: python3 network_test.py client <local_ip> <remote_ip>")
        print("  Port check:  python3 network_test.py ports")
        print()
        print("Examples:")
        print("  VM2 (responder): python3 network_test.py server 192.168.1.20")
        print("  VM1 (initiator): python3 network_test.py client 192.168.1.10 192.168.1.20")
        return
    
    mode = sys.argv[1]
    
    if mode == "server":
        if len(sys.argv) < 3:
            print("Server mode requires local IP")
            return
        local_ip = sys.argv[2]
        test_udp_server(local_ip, 5002)  # VPN responder port
        
    elif mode == "client":
        if len(sys.argv) < 4:
            print("Client mode requires local IP and remote IP")
            return
        local_ip = sys.argv[2]
        remote_ip = sys.argv[3]
        success = test_udp_client(local_ip, remote_ip, 5002)
        if success:
            print(f"[CLIENT] ✅ Network connectivity test PASSED")
        else:
            print(f"[CLIENT] ❌ Network connectivity test FAILED")
            
    elif mode == "ports":
        check_firewall_ports()
        
    else:
        print(f"Unknown mode: {mode}")

if __name__ == "__main__":
    main()
