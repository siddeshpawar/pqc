#!/usr/bin/env python3
"""
Quick Certificate Diagnostic Script
Check if certificates are in the expected ML-DSA format
"""

import os
import sys
import subprocess

def check_certificate(cert_path):
    """Check certificate format and content"""
    print(f"\n=== Checking Certificate: {cert_path} ===")
    
    if not os.path.exists(cert_path):
        print("❌ Certificate file not found")
        return False
    
    try:
        # Check certificate details
        cmd = ['openssl', 'x509', '-in', cert_path, '-text', '-noout']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            print(f"❌ OpenSSL cannot read certificate: {result.stderr}")
            return False
        
        cert_text = result.stdout
        print("✅ Certificate is readable by OpenSSL")
        
        # Check for ML-DSA indicators
        mldsa_indicators = [
            "ML-DSA", "MLDSA", "1.3.6.1.4.1.2.267.12",
            "dilithium", "post-quantum"
        ]
        
        found_indicators = []
        for indicator in mldsa_indicators:
            if indicator.lower() in cert_text.lower():
                found_indicators.append(indicator)
        
        if found_indicators:
            print(f"✅ Found ML-DSA indicators: {found_indicators}")
        else:
            print("❌ No ML-DSA indicators found")
            
            # Check what algorithm it actually is
            if "RSA" in cert_text:
                print("ℹ️  Certificate appears to be RSA-based")
            elif "ECDSA" in cert_text or "EC" in cert_text:
                print("ℹ️  Certificate appears to be ECDSA/EC-based")
            else:
                print("ℹ️  Certificate algorithm unclear")
        
        # Extract and show subject
        lines = cert_text.split('\n')
        for line in lines:
            if 'Subject:' in line:
                print(f"ℹ️  {line.strip()}")
                break
        
        # Extract and show issuer
        for line in lines:
            if 'Issuer:' in line:
                print(f"ℹ️  {line.strip()}")
                break
        
        # Check signature algorithm
        for line in lines:
            if 'Signature Algorithm:' in line:
                print(f"ℹ️  {line.strip()}")
                break
        
        return len(found_indicators) > 0
        
    except Exception as e:
        print(f"❌ Error checking certificate: {e}")
        return False

def check_private_key(key_path):
    """Check private key format"""
    print(f"\n=== Checking Private Key: {key_path} ===")
    
    if not os.path.exists(key_path):
        print("❌ Private key file not found")
        return False
    
    try:
        # Check key details
        cmd = ['openssl', 'pkey', '-in', key_path, '-text', '-noout']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            print(f"❌ OpenSSL cannot read private key: {result.stderr}")
            return False
        
        key_text = result.stdout
        print("✅ Private key is readable by OpenSSL")
        
        # Check key type
        if "RSA" in key_text:
            print("ℹ️  Private key appears to be RSA")
        elif "EC" in key_text:
            print("ℹ️  Private key appears to be EC/ECDSA")
        elif "ML-DSA" in key_text or "dilithium" in key_text.lower():
            print("✅ Private key appears to be ML-DSA")
        else:
            print("❌ Private key type unclear")
        
        return True
        
    except Exception as e:
        print(f"❌ Error checking private key: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 check_certificates.py <cert_dir>")
        print("Example: python3 check_certificates.py pqc_ipsec")
        sys.exit(1)
    
    cert_dir = sys.argv[1]
    print(f"Certificate Directory Diagnostic: {cert_dir}")
    print("=" * 50)
    
    # Check client certificates
    client_dir = os.path.join(cert_dir, "client")
    if os.path.exists(client_dir):
        print(f"\n📁 CLIENT DIRECTORY: {client_dir}")
        for file in os.listdir(client_dir):
            if file.endswith('.cert.pem') or file.endswith('.crt'):
                cert_path = os.path.join(client_dir, file)
                check_certificate(cert_path)
            elif file.endswith('.key.pem') or file.endswith('.key'):
                key_path = os.path.join(client_dir, file)
                check_private_key(key_path)
    
    # Check server certificates
    server_dir = os.path.join(cert_dir, "server")
    if os.path.exists(server_dir):
        print(f"\n📁 SERVER DIRECTORY: {server_dir}")
        for file in os.listdir(server_dir):
            if file.endswith('.cert.pem') or file.endswith('.crt'):
                cert_path = os.path.join(server_dir, file)
                check_certificate(cert_path)
            elif file.endswith('.key.pem') or file.endswith('.key'):
                key_path = os.path.join(server_dir, file)
                check_private_key(key_path)
    
    print(f"\n" + "=" * 50)
    print("SUMMARY:")
    print("If you see ❌ 'No ML-DSA indicators found', your certificates are")
    print("traditional (RSA/ECDSA) certificates, not ML-DSA certificates.")
    print("\nFor ML-DSA VPN to work properly, you need:")
    print("1. ML-DSA certificates generated with post-quantum tools")
    print("2. ML-DSA private keys")
    print("3. Certificate chains with ML-DSA signatures")

if __name__ == "__main__":
    main()
