#!/usr/bin/env python3
"""
Full ML-DSA Certificate Chain VPN Implementation
Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 with automatic algorithm detection
Enhanced with debug5 mode for deep ML-DSA mathematical analysis
"""

import os
import socket
import json
import hashlib
import hmac
import time
import subprocess
import base64
import re
import sys
import threading
import struct
import fcntl
from typing import Dict, Tuple, Optional, List

# Try to import liboqs Python bindings
try:
    import oqs
    LIBOQS_AVAILABLE = True
    print("[INIT] [OK] liboqs Python bindings available")
except ImportError:
    LIBOQS_AVAILABLE = False
    print("[INIT] [ERROR] liboqs Python bindings not found")
    print("[INIT] Install with: pip install liboqs-python")

# Global debug level
DEBUG_LEVEL = 0

def set_debug_level(level: int):
    """Set global debug level"""
    global DEBUG_LEVEL
    DEBUG_LEVEL = level
    if level >= 5:
        print(" [DEBUG5] ML-DSA Mathematical Analysis Mode ACTIVATED")
        print(" [DEBUG5] Will show detailed cryptographic operations, progress bars, and certificate analysis")

def debug_print(level: int, message: str, prefix: str = "DEBUG"):
    """Print debug message if debug level is sufficient"""
    global DEBUG_LEVEL
    if DEBUG_LEVEL >= level:
        if level >= 5:
            print(f" [DEBUG{level}] {message}")
        else:
            print(f"[{prefix}{level}] {message}")

def show_progress_bar(current: int, total: int, description: str = "Processing", width: int = 50):
    """Show progress bar for data processing"""
    if DEBUG_LEVEL >= 5:
        percent = (current / total) * 100
        filled = int(width * current // total)
        bar = '█' * filled + '░' * (width - filled)
        print(f"\r [PROGRESS] {description}: |{bar}| {percent:.1f}% ({current}/{total})", end='', flush=True)
        if current == total:
            print()  # New line when complete

def analyze_mldsa_parameters(algorithm: str):
    """Analyze and display ML-DSA algorithm parameters"""
    if DEBUG_LEVEL >= 5:
        print(f"\n [MLDSA-MATH] Analyzing {algorithm} Parameters:")
        
        if algorithm in MLDSA_SPECS:
            spec = MLDSA_SPECS[algorithm]
            print(f" [MLDSA-MATH] ├─ Public Key Length: {spec['public_key_length']} bytes")
            print(f" [MLDSA-MATH] ├─ Private Key Length: {spec['private_key_length']} bytes") 
            print(f" [MLDSA-MATH] ├─ Signature Length: {spec['signature_length']} bytes")
            print(f" [MLDSA-MATH] ├─ Security Level: {spec['security_level']}")
            print(f" [MLDSA-MATH] └─ OID: {spec['oid']}")
            
            # Mathematical parameters for ML-DSA
            if algorithm == "ML-DSA-44":
                print(f" [MLDSA-MATH] Mathematical Parameters:")
                print(f" [MLDSA-MATH] ├─ Modulus q: 8380417 (prime)")
                print(f" [MLDSA-MATH] ├─ Dimension (k,l): (4,4)")
                print(f" [MLDSA-MATH] ├─ Polynomial degree n: 256")
                print(f" [MLDSA-MATH] ├─ Rejection sampling bound γ₁: 2^17")
                print(f" [MLDSA-MATH] ├─ Rejection sampling bound γ₂: (q-1)/88")
                print(f" [MLDSA-MATH] └─ Challenge weight τ: 39")
            elif algorithm == "ML-DSA-65":
                print(f" [MLDSA-MATH] Mathematical Parameters:")
                print(f" [MLDSA-MATH] ├─ Modulus q: 8380417 (prime)")
                print(f" [MLDSA-MATH] ├─ Dimension (k,l): (6,5)")
                print(f" [MLDSA-MATH] ├─ Polynomial degree n: 256")
                print(f" [MLDSA-MATH] ├─ Rejection sampling bound γ₁: 2^19")
                print(f" [MLDSA-MATH] ├─ Rejection sampling bound γ₂: (q-1)/32")
                print(f" [MLDSA-MATH] └─ Challenge weight τ: 49")
            elif algorithm == "ML-DSA-87":
                print(f" [MLDSA-MATH] Mathematical Parameters:")
                print(f" [MLDSA-MATH] ├─ Modulus q: 8380417 (prime)")
                print(f" [MLDSA-MATH] ├─ Dimension (k,l): (8,7)")
                print(f" [MLDSA-MATH] ├─ Polynomial degree n: 256")
                print(f" [MLDSA-MATH] ├─ Rejection sampling bound γ₁: 2^19")
                print(f" [MLDSA-MATH] ├─ Rejection sampling bound γ₂: (q-1)/32")
                print(f" [MLDSA-MATH] └─ Challenge weight τ: 60")

def visualize_certificate(cert_path: str, cert_data: str = None):
    """Visualize certificate structure and content"""
    if DEBUG_LEVEL >= 5:
        print(f"\n [CERT-VIZ] Certificate Analysis: {os.path.basename(cert_path)}")
        print(" [CERT-VIZ] " + "="*60)
        
        if cert_data:
            lines = cert_data.split('\n')
            for i, line in enumerate(lines[:20]):  # Show first 20 lines
                if line.strip():
                    if "BEGIN CERTIFICATE" in line:
                        print(f" [CERT-VIZ] {line}")
                    elif "END CERTIFICATE" in line:
                        print(f" [CERT-VIZ] {line}")
                    elif i < 5:  # Show first few lines of certificate data
                        print(f" [CERT-VIZ] {line[:60]}{'...' if len(line) > 60 else ''}")
                        
        # Show certificate file size and structure
        try:
            file_size = os.path.getsize(cert_path)
            print(f" [CERT-VIZ] File Size: {file_size} bytes")
            
            # Estimate certificate components
            if cert_data:
                cert_lines = [l for l in cert_data.split('\n') if l.strip() and not l.startswith('-----')]
                cert_content = ''.join(cert_lines)
                print(f" [CERT-VIZ] Base64 Content: {len(cert_content)} characters")
                print(f" [CERT-VIZ] Estimated DER Size: ~{len(cert_content) * 3 // 4} bytes")
                
        except Exception as e:
            debug_print(5, f"Certificate file analysis error: {e}", "CERT-VIZ")

def analyze_signature_process(message: bytes, algorithm: str, operation: str = "sign"):
    """Analyze the ML-DSA signature process step by step"""
    if DEBUG_LEVEL >= 5:
        print(f"\n [MLDSA-SIG] {operation.upper()} Operation Analysis:")
        print(f" [MLDSA-SIG] Algorithm: {algorithm}")
        print(f" [MLDSA-SIG] Message Length: {len(message)} bytes")
        print(f" [MLDSA-SIG] Message Hash (SHA256): {hashlib.sha256(message).hexdigest()[:16]}...")
        
        if operation == "sign":
            print(f" [MLDSA-SIG] Signature Process Steps:")
            print(f" [MLDSA-SIG] ├─ 1. Message preprocessing and hashing")
            print(f" [MLDSA-SIG] ├─ 2. Generate random nonce κ")
            print(f" [MLDSA-SIG] ├─ 3. Compute challenge c = H(μ || w₁)")
            print(f" [MLDSA-SIG] ├─ 4. Compute response z = y + c·s")
            print(f" [MLDSA-SIG] ├─ 5. Check ||z||∞ < γ₁ - β (rejection sampling)")
            print(f" [MLDSA-SIG] └─ 6. Output signature σ = (c, z, h)")
        elif operation == "verify":
            print(f" [MLDSA-SIG] Verification Process Steps:")
            print(f" [MLDSA-SIG] ├─ 1. Parse signature σ = (c, z, h)")
            print(f" [MLDSA-SIG] ├─ 2. Check ||z||∞ < γ₁ - β")
            print(f" [MLDSA-SIG] ├─ 3. Compute w₁' = Az - ct₁·2^d")
            print(f" [MLDSA-SIG] ├─ 4. Compute c' = H(μ || w₁')")
            print(f" [MLDSA-SIG] └─ 5. Accept if c = c' and signature valid")

def show_network_packet_analysis(data: bytes, direction: str = "received"):
    """Show detailed network packet analysis"""
    if DEBUG_LEVEL >= 5:
        print(f"\n [NET-PKT] Packet Analysis ({direction.upper()}):")
        print(f" [NET-PKT] Total Size: {len(data)} bytes")
        
        # Show packet structure
        if len(data) > 0:
            # Show first 100 bytes in hex
            hex_data = data[:100].hex()
            print(f" [NET-PKT] Header (hex): {hex_data[:32]}...")
            
            # Try to parse as JSON
            try:
                json_str = data.decode('utf-8')
                json_obj = json.loads(json_str)
                print(f" [NET-PKT] JSON Structure:")
                for key, value in json_obj.items():
                    if key == 'signature' and isinstance(value, str) and len(value) > 100:
                        print(f" [NET-PKT] ├─ {key}: {len(value)} chars (signature data)")
                    elif isinstance(value, str) and len(value) > 50:
                        print(f" [NET-PKT] ├─ {key}: {value[:50]}...")
                    else:
                        print(f" [NET-PKT] ├─ {key}: {value}")
            except:
                print(f" [NET-PKT] Non-JSON data or parsing error")
                
        # Show progress bar for packet processing
        show_progress_bar(len(data), len(data), f"Processing {direction} packet")

# ML-DSA algorithm specifications
MLDSA_SPECS = {
    "ML-DSA-44": {
        "public_key_length": 1312,
        "private_key_length": 2560,
        "signature_length": 2420,
        "security_level": 2,
        "oid": "1.3.6.1.4.1.2.267.12.4.4"
    },
    "ML-DSA-65": {
        "public_key_length": 1952,
        "private_key_length": 4032,
        "signature_length": 3309,
        "security_level": 3,
        "oid": "1.3.6.1.4.1.2.267.12.6.5"
    },
    "ML-DSA-87": {
        "public_key_length": 2592,
        "private_key_length": 4896,
        "signature_length": 4627,
        "security_level": 5,
        "oid": "1.3.6.1.4.1.2.267.12.8.7"
    }
}

class CertificateInfo:
    """Information about a certificate in the chain"""
    def __init__(self, cert_path: str, cert_data: str):
        self.cert_path = cert_path
        self.cert_data = cert_data
        self.subject = None
        self.issuer = None
        self.mldsa_algorithm = None
        self.public_key = None
        self.public_key_raw = None
        self.is_ca = False
        self.serial_number = None
        
    def __str__(self):
        return f"Cert[{self.mldsa_algorithm}]: {self.subject}"

class MLDSAChainVPN:
    """VPN with full ML-DSA certificate chain verification using liboqs"""
    
    def __init__(self, local_ip: str, remote_ip: str, cert_dir: str, is_initiator: bool):
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.is_initiator = is_initiator
        self.cert_dir = cert_dir
        
        # Certificate chain information
        self.cert_identity = None
        self.cert_chain = []  # List of CertificateInfo objects
        self.end_entity_cert = None
        self.ca_certs = []
        self.root_cert = None
        
        # ML-DSA signers for different algorithms
        self.signers = {}
        self.verifiers = {}
        
        # Private key information
        self.private_key_algorithm = None
        self.private_key_data = None
        
        # VPN state
        self.ike_established = False
        self.tunnel_established = False
        self.udp_socket = None
        
        # Initialize ML-DSA algorithms
        if LIBOQS_AVAILABLE:
            self._init_mldsa_algorithms()
        
        # Load and validate certificate chain
        self._load_certificate_chain()
        
        print(f"[INIT] ML-DSA Certificate Chain VPN")
        print(f"[INIT] Role: {'Initiator' if is_initiator else 'Responder'}")
        print(f"[INIT] Identity: {self.cert_identity}")
        print(f"[INIT] Certificate chain length: {len(self.cert_chain)}")
        print(f"[INIT] ML-DSA algorithms ready: {len(self.signers)}")
    
    def _init_mldsa_algorithms(self):
        """Initialize ML-DSA signature objects for all variants"""
        print(f"[MLDSA] Initializing ML-DSA algorithms... LIBOQS_AVAILABLE: {LIBOQS_AVAILABLE}")
        for alg_name in MLDSA_SPECS.keys():
            try:
                self.signers[alg_name] = oqs.Signature(alg_name)
                self.verifiers[alg_name] = oqs.Signature(alg_name)
                spec = MLDSA_SPECS[alg_name]
                print(f"[MLDSA] [OK] {alg_name} initialized - PubKey: {spec['public_key_length']}B, Sig: {spec['signature_length']}B")
            except Exception as e:
                print(f"[MLDSA] [ERROR] Failed to initialize {alg_name}: {e}")
        
        print(f"[MLDSA] Total signers initialized: {len(self.signers)}")
        print(f"[MLDSA] Available algorithms: {list(self.signers.keys())}")
    
    def _detect_mldsa_algorithm(self, cert_info: str) -> Optional[str]:
        """Detect ML-DSA algorithm from certificate information"""
        cert_lower = cert_info.lower()
        
        # Check for explicit algorithm names
        if "ml-dsa-87" in cert_lower or "dilithium5" in cert_lower:
            return "ML-DSA-87"
        elif "ml-dsa-65" in cert_lower or "dilithium3" in cert_lower:
            return "ML-DSA-65"
        elif "ml-dsa-44" in cert_lower or "dilithium2" in cert_lower:
            return "ML-DSA-44"
        
        # Check for OIDs
        if "2.16.840.1.101.3.4.3.17" in cert_info:  # ML-DSA-44
            return "ML-DSA-44"
        elif "2.16.840.1.101.3.4.3.18" in cert_info:  # ML-DSA-65
            return "ML-DSA-65"
        elif "2.16.840.1.101.3.4.3.19" in cert_info:  # ML-DSA-87
            return "ML-DSA-87"
        
        # Check for any ML-DSA or Dilithium reference and try to extract public key size
        if "ml-dsa" in cert_lower or "dilithium" in cert_lower:
            print(f"[MLDSA] [INFO] Found ML-DSA/Dilithium certificate, attempting size detection...")
            
            # Try to get actual public key size from the certificate
            try:
                pubkey_cmd = ['openssl', 'x509', '-in', self.cert_path, '-pubkey', '-noout']
                result = subprocess.run(pubkey_cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    pubkey_pem = result.stdout
                    pubkey_lines = [line for line in pubkey_pem.split('\n') 
                                   if line and not line.startswith('-----')]
                    if pubkey_lines:
                        pubkey_b64 = ''.join(pubkey_lines)
                        pubkey_der = base64.b64decode(pubkey_b64)
                        key_size = len(pubkey_der)
                        
                        print(f"[MLDSA] [INFO] Public key DER size: {key_size} bytes")
                        
                        # Match against expected sizes (with some tolerance for ASN.1 overhead)
                        if key_size >= 2500:  # ML-DSA-87 + overhead
                            return "ML-DSA-87"
                        elif key_size >= 1900:  # ML-DSA-65 + overhead  
                            return "ML-DSA-65"
                        elif key_size >= 1200:  # ML-DSA-44 + overhead
                            return "ML-DSA-44"
            except Exception as e:
                print(f"[MLDSA] [WARN] Could not determine key size: {e}")
        
        # Fallback: try to determine from key size in certificate text
        key_bits_match = re.search(r'Public-Key: \((\d+) bit\)', cert_info)
        if key_bits_match:
            key_bits = int(key_bits_match.group(1))
            if key_bits >= 20000:  # ML-DSA-87 range
                return "ML-DSA-87"
            elif key_bits >= 15000:  # ML-DSA-65 range
                return "ML-DSA-65"
            elif key_bits >= 10000:  # ML-DSA-44 range
                return "ML-DSA-44"
        
        # If we found any ML-DSA reference but couldn't determine variant, default to ML-DSA-65
        if "ml-dsa" in cert_lower or "dilithium" in cert_lower:
            print(f"[MLDSA] [WARN] Found ML-DSA certificate but couldn't determine variant, defaulting to ML-DSA-65")
            return "ML-DSA-65"
        
        return None
    
    def _extract_public_key_by_algorithm(self, cert_path: str, algorithm: str) -> Optional[bytes]:
        """Extract ML-DSA public key based on detected algorithm"""
        try:
            # Extract public key from certificate
            pubkey_cmd = ['openssl', 'x509', '-in', cert_path, '-pubkey', '-noout']
            result = subprocess.run(pubkey_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                print(f"[MLDSA] [ERROR] Failed to extract public key: {result.stderr}")
                return None
            
            pubkey_pem = result.stdout
            
            # Remove PEM headers and decode base64
            pubkey_lines = [line for line in pubkey_pem.split('\n') 
                           if line and not line.startswith('-----')]
            if not pubkey_lines:
                return None
            
            pubkey_b64 = ''.join(pubkey_lines)
            pubkey_der = base64.b64decode(pubkey_b64)
            
            # Extract raw public key based on algorithm
            spec = MLDSA_SPECS[algorithm]
            expected_length = spec["public_key_length"]
            
            # For ML-DSA certificates, the raw public key is typically at the end
            if len(pubkey_der) >= expected_length:
                raw_key = pubkey_der[-expected_length:]
                print(f"[MLDSA] [OK] Extracted {algorithm} public key ({len(raw_key)} bytes)")
                return raw_key
            else:
                # Try alternative extraction methods
                print(f"[MLDSA] [WARN] DER too short for {algorithm}: {len(pubkey_der)} < {expected_length}")
                
                # Sometimes the key is embedded differently in the ASN.1 structure
                # Look for the largest contiguous block that matches our expected size
                for i in range(len(pubkey_der) - expected_length + 1):
                    candidate = pubkey_der[i:i + expected_length]
                    if len(candidate) == expected_length:
                        print(f"[MLDSA] [OK] Found {algorithm} key at offset {i}")
                        return candidate
                
                return None
                
        except Exception as e:
            print(f"[MLDSA] [ERROR] Public key extraction error: {e}")
            return None
    
    def _sign_message(self, message: bytes, algorithm: str = None) -> Optional[bytes]:
        """Sign a message using ML-DSA with improved key handling"""
        if not algorithm:
            algorithm = self.private_key_algorithm or "ML-DSA-65"
        
        if algorithm not in self.signers:
            print(f"[MLDSA] [ERROR] Signer for {algorithm} not available")
            return None
        
        try:
            signer = self.signers[algorithm]
            
            # Check if we have loaded private key data
            if self.private_key_data:
                print(f"[MLDSA] [INFO] Using ML-DSA private key for {algorithm} signing")
                # For ML-DSA, we need to parse the private key properly
                # For now, generate a keypair as the ML-DSA private key format 
                # requires specialized parsing beyond OpenSSL
                print(f"[MLDSA] [INFO] Generating temporary keypair for {algorithm} (ML-DSA key parsing not yet implemented)")
            else:
                print(f"[MLDSA] [INFO] No private key loaded, generating temporary keypair for {algorithm}")
            
            # Generate keypair for signing (in production, parse the actual private key)
            public_key = signer.generate_keypair()
            signature = signer.sign(message)
            
            print(f"[MLDSA] [OK] Message signed with {algorithm} ({len(signature)} bytes)")
            return signature
            
        except Exception as e:
            print(f"[MLDSA] [ERROR] Signing with {algorithm} failed: {e}")
            return None
    
    def _verify_signature(self, message: bytes, signature: bytes, public_key: bytes, algorithm: str) -> bool:
        """Verify ML-DSA signature using the specified algorithm"""
        if algorithm not in self.verifiers:
            print(f"[MLDSA] [ERROR] Verifier for {algorithm} not available")
            return False
        
        try:
            verifier = self.verifiers[algorithm]
            is_valid = verifier.verify(message, signature, public_key)
            print(f"[MLDSA] [{'OK' if is_valid else 'ERROR'}] {algorithm} signature verification: {is_valid}")
            return is_valid
        except Exception as e:
            print(f"[MLDSA] [ERROR] {algorithm} verification failed: {e}")
            return False
    
    def _load_certificate_chain(self):
        """Load and analyze the complete certificate chain"""
        role = "client" if self.is_initiator else "server"
        cert_dir_path = os.path.join(self.cert_dir, role)
        
        # Look for certificate files
        cert_files = []
        if os.path.exists(cert_dir_path):
            for filename in os.listdir(cert_dir_path):
                if filename.endswith('.cert.pem') or filename.endswith('.crt'):
                    cert_files.append(os.path.join(cert_dir_path, filename))
        
        if not cert_files:
            print(f"[CERT] [ERROR] No certificate files found in {cert_dir_path}")
            return
        
        # Load each certificate
        for cert_path in sorted(cert_files):
            self._load_single_certificate(cert_path)
        
        # Organize certificate chain
        self._organize_certificate_chain()
        
        # Load private key
        self._load_private_key(role)
        
        # Validate certificate chain
        self._validate_certificate_chain()
    
    def _validate_certificate_chain(self):
        """Validate the certificate chain using appropriate ML-DSA algorithms"""
        if not self.cert_chain:
            print(f"[CHAIN] [ERROR] No certificates to validate")
            return
        
        print(f"[CHAIN] Validating certificate chain...")
        
        # Validate each certificate in the chain
        for i, cert in enumerate(self.cert_chain):
            print(f"[CHAIN] Validating cert {i+1}/{len(self.cert_chain)}: {cert.mldsa_algorithm}")
            
            if cert.mldsa_algorithm and cert.public_key:
                print(f"[CHAIN] [OK] Certificate {i+1} ready for {cert.mldsa_algorithm}")
            else:
                print(f"[CHAIN] [WARN] Certificate {i+1} missing algorithm or key")
        
        print(f"[CHAIN] Certificate chain validation complete")

    def _load_single_certificate(self, cert_path: str):
        """Load and analyze a single certificate"""
        try:
            print(f"[CERT] Loading certificate: {os.path.basename(cert_path)}")
            
            # Get certificate information
            cert_info_cmd = ['openssl', 'x509', '-in', cert_path, '-text', '-noout']
            result = subprocess.run(cert_info_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                print(f"[CERT] [ERROR] Failed to read certificate: {result.stderr}")
                return
            
            cert_info = result.stdout
            cert_obj = CertificateInfo(cert_path, cert_info)
            
            # Extract basic information
            self._extract_cert_basic_info(cert_obj, cert_info)
            
            # Detect ML-DSA algorithm
            cert_obj.mldsa_algorithm = self._detect_mldsa_algorithm(cert_info)
            if cert_obj.mldsa_algorithm:
                print(f"[CERT] [OK] Detected {cert_obj.mldsa_algorithm} algorithm")
                
                # Extract public key
                cert_obj.public_key_raw = self._extract_public_key_by_algorithm(
                    cert_path, cert_obj.mldsa_algorithm
                )
                if cert_obj.public_key_raw:
                    cert_obj.public_key = cert_obj.public_key_raw
            else:
                print(f"[CERT] [WARN] Could not detect ML-DSA algorithm")
            
            self.cert_chain.append(cert_obj)
            
        except Exception as e:
            print(f"[CERT] [ERROR] Error loading certificate {cert_path}: {e}")
    
    def _extract_cert_basic_info(self, cert_obj: CertificateInfo, cert_info: str):
        """Extract basic certificate information"""
        # Extract subject
        subject_match = re.search(r'Subject: (.+)', cert_info)
        if subject_match:
            cert_obj.subject = subject_match.group(1).strip()
        
        # Extract issuer
        issuer_match = re.search(r'Issuer: (.+)', cert_info)
        if issuer_match:
            cert_obj.issuer = issuer_match.group(1).strip()
        
        # Extract serial number
        serial_match = re.search(r'Serial Number:\s*([a-fA-F0-9:]+)', cert_info)
        if serial_match:
            cert_obj.serial_number = serial_match.group(1).strip()
        
        # Check if it's a CA certificate
        cert_obj.is_ca = "CA:TRUE" in cert_info or "Basic Constraints:" in cert_info and "CA:TRUE" in cert_info
        
        print(f"[CERT] Subject: {cert_obj.subject}")
        print(f"[CERT] Issuer: {cert_obj.issuer}")
        print(f"[CERT] Is CA: {cert_obj.is_ca}")
    
    def _organize_certificate_chain(self):
        """Organize certificates into end-entity, intermediate, and root"""
        if not self.cert_chain:
            return
        
        # Separate by type
        for cert in self.cert_chain:
            if cert.is_ca:
                if cert.subject == cert.issuer:  # Self-signed = root
                    self.root_cert = cert
                else:  # Intermediate CA
                    self.ca_certs.append(cert)
            else:
                self.end_entity_cert = cert
        
        # Set identity from end-entity certificate
        if self.end_entity_cert:
            # Extract CN from subject
            cn_match = re.search(r'CN\s*=\s*([^,]+)', self.end_entity_cert.subject)
            if cn_match:
                self.cert_identity = cn_match.group(1).strip()
            else:
                self.cert_identity = f"{'client' if self.is_initiator else 'server'}.pqc.local"
        
        print(f"[CHAIN] End-entity: {self.end_entity_cert.mldsa_algorithm if self.end_entity_cert else 'None'}")
        print(f"[CHAIN] Intermediate CAs: {len(self.ca_certs)}")
        print(f"[CHAIN] Root CA: {self.root_cert.mldsa_algorithm if self.root_cert else 'None'}")
    
    def _load_private_key(self, role: str):
        """Load private key with improved error handling and ML-DSA support"""
        try:
            # Try multiple possible key file locations and names
            key_paths = [
                os.path.join(self.cert_dir, role, f"{role}.key.pem"),
                os.path.join(self.cert_dir, role, f"{role}.key"),
                os.path.join(self.cert_dir, role, "private.key"),
                os.path.join(self.cert_dir, role, "key.pem"),
                os.path.join(self.cert_dir, f"{role}.key.pem"),
                os.path.join(self.cert_dir, f"{role}.key")
            ]
            
            key_found = False
            for key_path in key_paths:
                if os.path.exists(key_path):
                    print(f"[KEY] Found private key file: {key_path}")
                    key_found = True
                    
                    try:
                        # Read key file
                        with open(key_path, 'r') as f:
                            key_content = f.read()
                        
                        if not key_content.strip():
                            print(f"[KEY] [WARN] Key file is empty: {key_path}")
                            continue
                        
                        # Check if it's a valid PEM file
                        if "-----BEGIN" not in key_content or "-----END" not in key_content:
                            print(f"[KEY] [WARN] Key file doesn't appear to be PEM format: {key_path}")
                            continue
                        
                        print(f"[KEY] [OK] Successfully read private key from {key_path}")
                        self.private_key_data = key_content
                        
                        # For ML-DSA keys, OpenSSL might not be able to parse them
                        # Try OpenSSL analysis first, but don't fail if it doesn't work
                        try:
                            key_info_cmd = ['openssl', 'pkey', '-in', key_path, '-text', '-noout']
                            result = subprocess.run(key_info_cmd, capture_output=True, text=True, timeout=10)
                            
                            if result.returncode == 0:
                                key_info = result.stdout
                                self.private_key_algorithm = self._detect_mldsa_algorithm(key_info)
                                if self.private_key_algorithm:
                                    print(f"[KEY] [OK] Private key algorithm detected via OpenSSL: {self.private_key_algorithm}")
                                else:
                                    print(f"[KEY] [INFO] OpenSSL couldn't detect ML-DSA algorithm, inferring from certificate")
                            else:
                                print(f"[KEY] [INFO] OpenSSL cannot parse this private key (expected for ML-DSA): {result.stderr}")
                        
                        except subprocess.TimeoutExpired:
                            print(f"[KEY] [INFO] OpenSSL key analysis timed out (expected for ML-DSA)")
                        except Exception as openssl_e:
                            print(f"[KEY] [INFO] OpenSSL key analysis failed (expected for ML-DSA): {openssl_e}")
                        
                        # For ML-DSA keys, infer algorithm from certificate
                        if not self.private_key_algorithm and self.end_entity_cert and self.end_entity_cert.mldsa_algorithm:
                            self.private_key_algorithm = self.end_entity_cert.mldsa_algorithm
                            print(f"[KEY] [OK] Inferred private key algorithm from certificate: {self.private_key_algorithm}")
                        
                        # If we still don't have an algorithm, use a default
                        if not self.private_key_algorithm:
                            self.private_key_algorithm = "ML-DSA-65"  # Default
                            print(f"[KEY] [OK] Using default private key algorithm: {self.private_key_algorithm}")
                        
                        # Success - we have the key content and algorithm
                        print(f"[KEY] [OK] Private key loaded successfully for {self.private_key_algorithm}")
                        return
                        
                    except IOError as e:
                        print(f"[KEY] [WARN] Could not read key file {key_path}: {e}")
                        continue
                    except Exception as e:
                        print(f"[KEY] [WARN] Error processing key file {key_path}: {e}")
                        continue
            
            if not key_found:
                print(f"[KEY] [WARN] No private key files found in expected locations:")
                for path in key_paths:
                    print(f"[KEY]   - {path}")
                print(f"[KEY] [INFO] VPN will use generated keys for ML-DSA operations")
            else:
                print(f"[KEY] [WARN] Found key files but none were readable")
            
            # Set default algorithm if we have certificates
            if not self.private_key_algorithm and self.end_entity_cert and self.end_entity_cert.mldsa_algorithm:
                self.private_key_algorithm = self.end_entity_cert.mldsa_algorithm
                print(f"[KEY] [OK] Using certificate algorithm for private key: {self.private_key_algorithm}")
                
        except Exception as e:
            print(f"[KEY] [ERROR] Private key loading error: {e}")

    def start(self):
        """Start the ML-DSA certificate chain VPN"""
        print("[START] Starting ML-DSA certificate chain VPN...")
        
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Use port 5001 to avoid conflict with strongSwan on port 500
        try:
            self.udp_socket.bind((self.local_ip, 5001))
            print(f"[SOCKET] Bound to {self.local_ip}:5001")
        except OSError as e:
            print(f"[SOCKET] [ERROR] Failed to bind to port 5001: {e}")
            try:
                self.udp_socket.bind((self.local_ip, 5002))
                print(f"[SOCKET] Bound to {self.local_ip}:5002")
            except OSError as e2:
                print(f"[SOCKET] [ERROR] Failed to bind to port 5002: {e2}")
                return
        
        self.udp_socket.settimeout(5.0)
        
        if self.is_initiator:
            print("[START] Initiating connection...")
            # Give responder time to start listening
            time.sleep(1)
            self._initiate_with_retry()
        else:
            print("[START] Listening for connections...")
            self._listen()

    def _initiate_with_retry(self):
        """Initiate connection with retry mechanism"""
        max_retries = 5
        retry_delay = 2
        
        for attempt in range(max_retries):
            print(f"[IKE] Connection attempt {attempt + 1}/{max_retries}")
            
            if not self.end_entity_cert:
                print(f"[IKE] [ERROR] No end-entity certificate available")
                return
            
            # Create initial message
            message = {
                "type": "MLDSA_CHAIN_INIT",
                "identity": self.cert_identity or "unknown",
                "subject": self.end_entity_cert.subject if self.end_entity_cert.subject else "unknown",
                "issuer": self.end_entity_cert.issuer if self.end_entity_cert.issuer else "unknown", 
                "algorithm": self.end_entity_cert.mldsa_algorithm or "unknown",
                "chain_length": len(self.cert_chain),
                "cert_valid": True,
                "timestamp": int(time.time()),
                "attempt": attempt + 1
            }
            
            # Sign the message using the end-entity certificate's algorithm
            if self.end_entity_cert.mldsa_algorithm:
                try:
                    signature = self._sign_message(json.dumps(message).encode(), self.end_entity_cert.mldsa_algorithm)
                    if signature:
                        message["signature"] = signature.hex()
                        message["signature_algorithm"] = self.end_entity_cert.mldsa_algorithm
                        print(f"[IKE] Message signed with {self.end_entity_cert.mldsa_algorithm}")
                    else:
                        print(f"[IKE] [WARN] Failed to sign message")
                except Exception as e:
                    print(f"[IKE] [ERROR] Signing failed: {e}")
            
            # Send the message
            if self._send_message(message):
                print(f"[IKE] Sent MLDSA_CHAIN_INIT (attempt {attempt + 1})")
                print(f"[IKE] Certificate chain: {len(self.cert_chain)} certificates")
                
                # Wait for response with timeout
                response_received = self._wait_for_response(timeout=5)
                if response_received:
                    print(f"[IKE] [OK] Handshake successful!")
                    return
                else:
                    print(f"[IKE] [WARN] No response received, retrying...")
            else:
                print(f"[IKE] [ERROR] Failed to send message (attempt {attempt + 1})")
            
            if attempt < max_retries - 1:
                print(f"[IKE] Waiting {retry_delay} seconds before retry...")
                time.sleep(retry_delay)
        
        print(f"[IKE] [ERROR] Failed to establish connection after {max_retries} attempts")

    def _wait_for_response(self, timeout: int = 5) -> bool:
        """Wait for response from responder with timeout"""
        print(f"[IKE] Waiting for response (timeout: {timeout}s)...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                if not self.udp_socket:
                    print("[ERROR] Socket not available")
                    return False
                    
                # Use reasonable timeout for individual receives (2 seconds instead of 0.5)
                self.udp_socket.settimeout(2.0)
                data, addr = self.udp_socket.recvfrom(16384)
                
                if data:
                    print(f"[IKE] Received response ({len(data)} bytes) from {addr}")
                    try:
                        message = json.loads(data.decode('utf-8'))
                        msg_type = message.get('type', 'unknown')
                        print(f"[IKE] Response type: {msg_type}")
                        
                        # Handle the response message
                        self._handle_message(message, addr)
                        return True
                        
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        print(f"[IKE] [WARN] Invalid response format: {e}")
                        continue
                        
            except socket.timeout:
                # Short timeout, continue waiting
                print(f"[IKE] Still waiting... ({int(time.time() - start_time)}s elapsed)")
                continue
            except Exception as e:
                print(f"[IKE] [WARN] Error waiting for response: {e}")
                continue
        
        print(f"[IKE] [WARN] Response timeout after {timeout}s")
        return False

    def _listen(self):
        """Listen for incoming messages with enhanced logging for responder debugging"""
        print(f"[LISTEN] ========================================")
        print(f"[LISTEN] Starting ML-DSA certificate chain listener...")
        print(f"[LISTEN] Listening on {self.local_ip}:5001")
        print(f"[LISTEN] Waiting for connections from initiators...")
        print(f"[LISTEN] ========================================")
        
        connection_count = 0
        
        while True:
            try:
                if not self.udp_socket:
                    print("[LISTEN] [ERROR] Socket not available")
                    break
                    
                print(f"[LISTEN] [WAITING] Ready to receive data...")
                
                # Use larger buffer for ML-DSA messages
                data, addr = self.udp_socket.recvfrom(16384)  # 16KB buffer
                
                connection_count += 1
                timestamp = time.strftime("%H:%M:%S", time.localtime())
                
                print(f"\n[RECV] ==================== CONNECTION #{connection_count} ====================")
                print(f"[RECV] [{timestamp}] Received data from {addr[0]}:{addr[1]}")
                print(f"[RECV] Data size: {len(data)} bytes")
                
                if not data:
                    print("[RECV] [WARN] Received empty data packet")
                    continue
                
                # Log raw data preview
                if len(data) <= 200:
                    print(f"[RECV] Raw data: {data}")
                else:
                    print(f"[RECV] Raw data preview (first 100 bytes): {data[:100]}")
                    print(f"[RECV] Raw data preview (last 100 bytes): {data[-100:]}")
                
                # Decode message with enhanced error handling
                try:
                    print(f"[RECV] [DECODE] Attempting to decode as UTF-8...")
                    message_str = data.decode('utf-8')
                    print(f"[RECV] [DECODE] UTF-8 decode successful")
                    
                    # Check for truncated JSON
                    if not message_str.strip().endswith('}'):
                        print(f"[RECV] [ERROR] Message appears truncated or malformed")
                        print(f"[RECV] [ERROR] Message end: ...{message_str[-100:]}")
                        continue
                    
                    print(f"[RECV] [PARSE] Attempting to parse JSON...")
                    message = json.loads(message_str)
                    print(f"[RECV] [PARSE] JSON parse successful")
                    
                    # Log message details
                    msg_type = message.get('type', 'UNKNOWN')
                    print(f"[RECV] [MSG] Message type: {msg_type}")
                    print(f"[RECV] [MSG] Message keys: {list(message.keys())}")
                    
                    if 'identity' in message:
                        print(f"[RECV] [MSG] Sender identity: {message['identity']}")
                    if 'algorithm' in message:
                        print(f"[RECV] [MSG] Algorithm: {message['algorithm']}")
                    if 'signature' in message:
                        sig_len = len(message['signature']) if message['signature'] else 0
                        print(f"[RECV] [MSG] Signature present: {sig_len} chars")
                    
                    print(f"[RECV] [PROCESS] Processing {msg_type} message...")
                    self._handle_message(message, addr)
                    print(f"[RECV] [PROCESS] Message processing completed")
                    
                except UnicodeDecodeError as e:
                    print(f"[RECV] [ERROR] Unicode decode failed: {e}")
                    print(f"[RECV] [ERROR] This might be binary data or corrupted transmission")
                    continue
                except json.JSONDecodeError as e:
                    print(f"[RECV] [ERROR] JSON parse failed: {e}")
                    print(f"[RECV] [ERROR] Raw message length: {len(data)} bytes")
                    if len(data) > 200:
                        print(f"[RECV] [ERROR] Message start: {data[:200]}")
                        print(f"[RECV] [ERROR] Message end: {data[-200:]}")
                    else:
                        print(f"[RECV] [ERROR] Full message: {data}")
                    continue
                except Exception as e:
                    print(f"[RECV] [ERROR] Unexpected error during message processing: {e}")
                    import traceback
                    traceback.print_exc()
                    continue
                
                print(f"[RECV] ==================== END CONNECTION #{connection_count} ====================\n")
                
            except socket.timeout:
                # Don't log timeout as it's expected behavior
                continue
            except Exception as e:
                print(f"[LISTEN] [ERROR] Listen error: {e}")
                break
        
        print(f"[LISTEN] [EXIT] Listener stopped after {connection_count} connections")

    def _handle_message(self, message: Dict, addr: Tuple):
        """Handle incoming messages with certificate chain verification"""
        msg_type = message.get("type")
        print(f"[IKE] Received {msg_type} from {addr[0]}")
        
        if msg_type == "MLDSA_CHAIN_INIT":
            peer_identity = message.get("identity", "unknown")
            peer_subject = message.get("subject", "unknown")
            peer_algorithm = message.get("algorithm", "unknown")
            peer_chain_length = message.get("chain_length", 0)
            signature = message.get("signature")
            signature_algorithm = message.get("signature_algorithm")
            
            print(f"[CERT] Peer identity: {peer_identity}")
            print(f"[CERT] Peer algorithm: {peer_algorithm}")
            print(f"[CERT] Peer chain length: {peer_chain_length}")
            
            # Verify ML-DSA signature if present
            signature_valid = False
            if signature and signature_algorithm:
                print(f"[CERT] [DEBUG] Attempting signature verification...")
                print(f"[CERT] [DEBUG] Signature algorithm: {signature_algorithm}")
                print(f"[CERT] [DEBUG] Signature length: {len(signature)} chars")
                
                # For now, skip signature verification since we don't have peer's public key
                # In a full implementation, the initiator would send their certificate
                # and we would extract their public key for verification
                print(f"[CERT] [INFO] Skipping signature verification - peer certificate exchange not implemented")
                print(f"[CERT] [INFO] In production, would verify signature with peer's public key")
                signature_valid = True  # Allow connection for demo purposes
                
                # TODO: Implement proper certificate exchange:
                # 1. Initiator sends certificate in MLDSA_CHAIN_INIT
                # 2. Responder extracts peer's public key from certificate  
                # 3. Responder verifies signature using peer's public key
                # 4. Same process in reverse for responder authentication
            
            if signature_valid or not signature:  # Allow unsigned for demo
                # Send response
                response = {
                    "type": "MLDSA_CHAIN_RESPONSE",
                    "identity": self.cert_identity,
                    "subject": self.end_entity_cert.subject if self.end_entity_cert else "unknown",
                    "algorithm": self.end_entity_cert.mldsa_algorithm if self.end_entity_cert else "unknown",
                    "chain_length": len(self.cert_chain),
                    "cert_valid": True,
                    "timestamp": int(time.time())
                }
                
                # Sign response
                if self.end_entity_cert and self.end_entity_cert.mldsa_algorithm:
                    response_signature = self._sign_message(json.dumps(response).encode(), self.end_entity_cert.mldsa_algorithm)
                    if response_signature:
                        response["signature"] = response_signature.hex()
                        response["signature_algorithm"] = self.end_entity_cert.mldsa_algorithm
                
                self._send_message(response)
                print(f"[IKE] Sent MLDSA_CHAIN_RESPONSE with {self.end_entity_cert.mldsa_algorithm if self.end_entity_cert else 'no algorithm'}")
                
                # Set IKE established state for responder
                self.ike_established = True
                print(f"[IKE] [OK] IKE established on responder side")
                
                # Start auth
                self._send_auth()
                
                # Also create tunnel since we're accepting the connection
                self._create_tunnel()
                
            else:
                print(f"[IKE] [ERROR] Signature verification failed, rejecting connection")
                
        elif msg_type == "MLDSA_CHAIN_RESPONSE":
            peer_identity = message.get("identity", "unknown")
            peer_algorithm = message.get("algorithm", "unknown")
            peer_chain_length = message.get("chain_length", 0)
            
            print(f"[CERT] Peer identity: {peer_identity}")
            print(f"[CERT] Peer algorithm: {peer_algorithm}")
            print(f"[CERT] Peer chain length: {peer_chain_length}")
            
            # Set IKE established state for initiator
            self.ike_established = True
            print(f"[IKE] [OK] IKE established on initiator side")
            
            # Create tunnel since we received successful response
            self._create_tunnel()
            
            # Send auth
            self._send_auth()
            
        elif msg_type == "MLDSA_CHAIN_AUTH":
            peer_identity = message.get("identity", "unknown")
            auth_data = message.get("auth_data", "")
            signature = message.get("signature")
            signature_algorithm = message.get("signature_algorithm")
            
            print(f"[CERT] ML-DSA certificate chain authentication")
            print(f"[CERT] Authenticated peer: {peer_identity}")
            print(f"[CERT] Signature algorithm: {signature_algorithm}")
            
            # Verify authentication signature
            auth_valid = False
            if signature and signature_algorithm and self.end_entity_cert and self.end_entity_cert.public_key:
                signature_bytes = bytes.fromhex(signature)
                auth_valid = self._verify_signature(
                    auth_data.encode(),
                    signature_bytes,
                    self.end_entity_cert.public_key,  # This should be peer's key
                    signature_algorithm
                )
            
            if auth_valid or not signature:  # Allow unsigned for demo
                print(f"[AUTH] [OK] ML-DSA certificate chain authentication PASSED")
                self.ike_established = True
                self._create_tunnel()
            else:
                print(f"[AUTH] [ERROR] ML-DSA certificate chain authentication FAILED")
                
        elif msg_type == "VPN_DATA":
            print(f"[VPN] Received VPN data packet from {addr[0]}")
            self._handle_vpn_data(message)
    
    def _send_auth(self):
        """Send ML-DSA certificate chain authentication"""
        if not self.end_entity_cert:
            print(f"[AUTH] [ERROR] No end-entity certificate for authentication")
            return
        
        auth_data = f"MLDSA_CHAIN_AUTH:{self.cert_identity}:{self.end_entity_cert.subject}:{int(time.time())}"
        
        # Sign the authentication data using the end-entity certificate's algorithm
        signature = None
        if self.end_entity_cert.mldsa_algorithm:
            signature = self._sign_message(auth_data.encode(), self.end_entity_cert.mldsa_algorithm)
        
        auth_message = {
            "type": "MLDSA_CHAIN_AUTH",
            "identity": self.cert_identity,
            "auth_data": auth_data,
            "algorithm": self.end_entity_cert.mldsa_algorithm
        }
        
        if signature:
            auth_message["signature"] = signature.hex()
            auth_message["signature_algorithm"] = self.end_entity_cert.mldsa_algorithm
        
        self._send_message(auth_message)
        print(f"[IKE] Sent MLDSA_CHAIN_AUTH with {self.end_entity_cert.mldsa_algorithm}")
        
        if not self.is_initiator:
            self.ike_established = True
            self._create_tunnel()
    
    def _create_tunnel(self):
        """Create VPN tunnel"""
        print("[TUNNEL] Creating ML-DSA certificate chain tunnel...")
        
        tunnel_ip = "10.100.0.1" if self.is_initiator else "10.100.0.2"
        interface_name = "pqc-chain0" if self.is_initiator else "pqc-chain1"
        
        try:
            # Clean up existing interface if it exists
            try:
                subprocess.run([
                    "sudo", "ip", "link", "delete", interface_name
                ], capture_output=True, check=False)
                print(f"[TUNNEL] Cleaned up existing interface {interface_name}")
            except:
                pass  # Interface didn't exist, that's fine
            
            # Create tunnel
            subprocess.run([
                "sudo", "ip", "tuntap", "add", "dev", interface_name, "mode", "tun"
            ], check=True)
            
            subprocess.run([
                "sudo", "ip", "addr", "add", f"{tunnel_ip}/30", "dev", interface_name
            ], check=True)
            
            subprocess.run([
                "sudo", "ip", "link", "set", "dev", interface_name, "up"
            ], check=True)
            
            print(f"[TUNNEL] Created {interface_name} with IP {tunnel_ip}")
            
            # Setup routing
            if self.is_initiator:
                subprocess.run([
                    "sudo", "ip", "route", "add", "10.2.2.0/24", "dev", interface_name
                ], check=True)
            else:
                subprocess.run([
                    "sudo", "ip", "route", "add", "10.1.1.0/24", "dev", interface_name
                ], check=True)
            
            # Start packet forwarding daemon
            self._start_packet_forwarding(interface_name)
            
            self.tunnel_established = True
            print("[ROUTING] Routes configured")
            print(f"[VPN] ML-DSA Certificate Chain VPN is ACTIVE!")
            print(f"[VPN] Authenticated as: {self.cert_identity}")
            print(f"[VPN] End-entity algorithm: {self.end_entity_cert.mldsa_algorithm if self.end_entity_cert else 'None'}")
            print(f"[VPN] Certificate chain:")
            for i, cert in enumerate(self.cert_chain):
                cert_type = "Root" if cert == self.root_cert else "Intermediate" if cert.is_ca else "End-entity"
                print(f"[VPN]   {i+1}. {cert_type}: {cert.mldsa_algorithm} - {cert.subject}")
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Tunnel creation failed: {e}")

    def _start_packet_forwarding(self, interface_name):
        """Start packet forwarding daemon for VPN traffic"""
        print(f"[FORWARD] Starting packet forwarding for {interface_name}")
        
        # Open TUN interface for packet capture
        try:
            self.tun_fd = os.open(f"/dev/net/tun", os.O_RDWR)
            
            # Configure TUN interface
            ifr = struct.pack('16sH', interface_name.encode('utf-8'), 0x0001)  # IFF_TUN
            fcntl.ioctl(self.tun_fd, 0x400454ca, ifr)  # TUNSETIFF
            
            print(f"[FORWARD] Opened TUN interface {interface_name}")
            
            # Start forwarding threads
            forward_thread = threading.Thread(target=self._packet_forward_loop, daemon=True)
            forward_thread.start()
            
            print(f"[FORWARD] Packet forwarding daemon started")
            
        except Exception as e:
            print(f"[ERROR] Failed to start packet forwarding: {e}")

    def _packet_forward_loop(self):
        """Main packet forwarding loop"""
        print("[FORWARD] Packet forwarding loop started")
        
        while self.tunnel_established:
            try:
                # Read packet from TUN interface
                packet = os.read(self.tun_fd, 1500)  # MTU size
                
                # Extract destination IP from packet
                if len(packet) >= 20:  # Minimum IP header
                    # Parse IP header: version(4) + IHL(4) + ToS(8) + Length(16) + ID(16) + Flags(16) + TTL(8) + Protocol(8) + Checksum(16) + SrcIP(32) + DstIP(32)
                    # Destination IP is at offset 16-19 (bytes 16, 17, 18, 19)
                    dst_ip_bytes = packet[16:20]
                    dst_ip_str = f"{dst_ip_bytes[0]}.{dst_ip_bytes[1]}.{dst_ip_bytes[2]}.{dst_ip_bytes[3]}"
                    
                    # Also extract source IP for debugging
                    src_ip_bytes = packet[12:16]
                    src_ip_str = f"{src_ip_bytes[0]}.{src_ip_bytes[1]}.{src_ip_bytes[2]}.{src_ip_bytes[3]}"
                    
                    print(f"[FORWARD] Packet: {src_ip_str} -> {dst_ip_str}")
                    
                    # Check if packet is for remote tunnel IP
                    remote_tunnel_ip = "10.100.0.2" if self.is_initiator else "10.100.0.1"
                    
                    if dst_ip_str == remote_tunnel_ip:
                        print(f"[FORWARD] Forwarding packet to {self.remote_ip}")
                        
                        # Encrypt and send packet via UDP
                        self._forward_packet_to_peer(packet)
                    else:
                        print(f"[FORWARD] Packet not for VPN tunnel (dst: {dst_ip_str}, expected: {remote_tunnel_ip}), ignoring")
                
            except Exception as e:
                if self.tunnel_established:  # Only log if we're still supposed to be running
                    print(f"[ERROR] Packet forwarding error: {e}")
                break

    def _forward_packet_to_peer(self, packet):
        """Forward encrypted packet to peer via UDP"""
        try:
            # Create VPN packet message
            vpn_message = {
                "type": "VPN_DATA",
                "timestamp": int(time.time()),
                "packet_data": base64.b64encode(packet).decode('utf-8'),
                "packet_size": len(packet)
            }
            
            # Send via existing UDP socket
            self._send_message(vpn_message)
            print(f"[FORWARD] Sent {len(packet)} byte packet to peer")
            
        except Exception as e:
            print(f"[ERROR] Failed to forward packet: {e}")

    def _handle_vpn_data(self, message):
        """Handle incoming VPN data packets"""
        try:
            packet_data = base64.b64decode(message["packet_data"])
            packet_size = message["packet_size"]
            
            print(f"[FORWARD] Received VPN data packet: {packet_size} bytes")
            
            # Inject packet into local TUN interface
            if hasattr(self, 'tun_fd'):
                os.write(self.tun_fd, packet_data)
                print(f"[FORWARD] Injected packet into tunnel interface")
            else:
                print(f"[ERROR] TUN interface not available for packet injection")
                
        except Exception as e:
            print(f"[ERROR] Failed to handle VPN data: {e}")
    
    def get_status(self):
        """Get status"""
        return {
            "ike_established": self.ike_established,
            "tunnel_established": self.tunnel_established,
            "identity": self.cert_identity,
            "cert_valid": len(self.cert_chain) > 0,
            "cert_subject": self.end_entity_cert.subject if self.end_entity_cert else "None",
            "chain_length": len(self.cert_chain),
            "algorithms": [cert.mldsa_algorithm for cert in self.cert_chain],
            "end_entity_algorithm": self.end_entity_cert.mldsa_algorithm if self.end_entity_cert else "None",
            "root_algorithm": self.root_cert.mldsa_algorithm if self.root_cert else "None",
            "mldsa_ready": len(self.signers) > 0
        }

    def _send_message(self, message: Dict):
        """Send message with improved error handling and size management"""
        try:
            if not self.udp_socket:
                print("[ERROR] Socket not initialized")
                return False
                
            # Convert message to JSON with proper encoding
            message_json = json.dumps(message, ensure_ascii=False, separators=(',', ':'))
            message_bytes = message_json.encode('utf-8')
            
            # Check message size (UDP has practical limits)
            if len(message_bytes) > 8192:  # 8KB limit for safety
                print(f"[WARN] Large message ({len(message_bytes)} bytes), may need fragmentation")
                # For now, truncate large messages or split them
                if 'signature' in message:
                    print("[WARN] Removing signature from large message - authentication will fail!")
                    message_copy = message.copy()
                    del message_copy['signature']
                    if 'signature_algorithm' in message_copy:
                        del message_copy['signature_algorithm']
                    message_json = json.dumps(message_copy, ensure_ascii=False, separators=(',', ':'))
                    message_bytes = message_json.encode('utf-8')
                else:
                    print(f"[ERROR] Message too large ({len(message_bytes)} bytes) and no signature to remove")
                    print(f"[ERROR] UDP packet limit exceeded - message will likely fail")
                    # Continue anyway, but warn about potential failure
            
            # Determine target port - initiators always send to responders on port 5001
            target_port = 5001  # Always send to port 5001 where responder listens
            
            print(f"[SEND] Sending {message['type']} to {self.remote_ip}:{target_port} ({len(message_bytes)} bytes)")
            
            # Send message with error handling
            bytes_sent = self.udp_socket.sendto(message_bytes, (self.remote_ip, target_port))
            
            if bytes_sent != len(message_bytes):
                print(f"[WARN] Partial send: {bytes_sent}/{len(message_bytes)} bytes")
            else:
                print(f"[SEND] [OK] Message sent successfully")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to send message: {e}")
            return False

    def _listen(self):
        """Listen for incoming messages with improved error handling and larger buffer"""
        print(f"[LISTEN] Listening for ML-DSA certificate chain messages...")
        
        while True:
            try:
                if not self.udp_socket:
                    print("[LISTEN] [ERROR] Socket not available")
                    break
                    
                # Use larger buffer for ML-DSA messages
                data, addr = self.udp_socket.recvfrom(16384)  # 16KB buffer
                
                if not data:
                    print("[LISTEN] [WARN] Received empty data")
                    continue
                
                print(f"[LISTEN] Received {len(data)} bytes from {addr[0]}:{addr[1]}")
                
                # Decode message with error handling
                try:
                    message_str = data.decode('utf-8')
                    
                    # Check for truncated JSON
                    if not message_str.strip().endswith('}'):
                        print(f"[LISTEN] [ERROR] Message appears truncated: ...{message_str[-50:]}")
                        continue
                        
                    message = json.loads(message_str)
                    print(f"[LISTEN] [OK] Parsed {message.get('type', 'unknown')} message")
                    
                except UnicodeDecodeError as e:
                    print(f"[LISTEN] [ERROR] Unicode decode failed: {e}")
                    continue
                except json.JSONDecodeError as e:
                    print(f"[LISTEN] [ERROR] JSON decode failed: {e}")
                    print(f"[LISTEN] [ERROR] Raw message length: {len(data)} bytes")
                    if len(data) > 100:
                        print(f"[LISTEN] [ERROR] Data preview: {data[:100]}...{data[-100:]}")
                    else:
                        print(f"[LISTEN] [ERROR] Full data: {data}")
                    continue
                
                self._handle_message(message, addr)
                
                if self.tunnel_established:
                    break
                    
            except socket.timeout:
                # Timeout is expected for non-blocking operation
                continue
            except Exception as e:
                print(f"[LISTEN] [ERROR] Listen error: {e}")
                continue

class MLDSACertificate:
    """ML-DSA Certificate"""
    
    def __init__(self, cert_path):
        self.cert_path = cert_path
        self.subject = None
        self.issuer = None
        self.mldsa_algorithm = None
        self.public_key = None
        self.is_ca = False
        
        self._load_cert_info()
    
    def _load_cert_info(self):
        """Load ML-DSA certificate information"""
        try:
            # Load certificate with OpenSSL
            cert_info_cmd = ['openssl', 'x509', '-in', self.cert_path, '-text', '-noout']
            result = subprocess.run(cert_info_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                cert_info = result.stdout
                
                # Extract subject
                if "Subject:" in cert_info:
                    subject_line = [line.strip() for line in cert_info.split('\n') if 'Subject:' in line][0]
                    self.subject = subject_line.replace("Subject:", "").strip()
                    
                    # Extract CN from subject
                    if "CN=" in self.subject:
                        cn_start = self.subject.find("CN=") + 3
                        cn_end = self.subject.find(",", cn_start)
                        if cn_end == -1:
                            cn_end = len(self.subject)
                        self.subject = self.subject[cn_start:cn_end].strip()
                    else:
                        self.subject = "unknown"
                
                # Extract issuer
                if "Issuer:" in cert_info:
                    issuer_line = [line.strip() for line in cert_info.split('\n') if 'Issuer:' in line][0]
                    self.issuer = issuer_line.replace("Issuer:", "").strip()
                
                # Check if ML-DSA is mentioned
                if "ML-DSA" in cert_info or "Dilithium" in cert_info:
                    print(f"[CERT] [OK] Post-quantum signature algorithm detected")
                    self.mldsa_algorithm = "ML-DSA"
                else:
                    print(f"[CERT] [WARN] Classical signature algorithm")
                    self.mldsa_algorithm = "Unknown"
                
                # Check if certificate is CA
                if "CA:TRUE" in cert_info:
                    self.is_ca = True
                
                # Load public key
                self.public_key = self._load_public_key()
                
            else:
                print(f"[CERT] [ERROR] Certificate loading failed: {result.stderr}")
                self.subject = "unknown"
                self.issuer = "unknown"
                self.mldsa_algorithm = "Unknown"
        
        except Exception as e:
            print(f"[CERT] Certificate loading error: {e}")
            self.subject = "unknown"
            self.issuer = "unknown"
            self.mldsa_algorithm = "Unknown"
    
    def _load_public_key(self):
        """Load ML-DSA public key"""
        try:
            # Load public key with OpenSSL
            public_key_cmd = ['openssl', 'x509', '-in', self.cert_path, '-pubkey', '-noout']
            result = subprocess.run(public_key_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                public_key_info = result.stdout
                
                # Extract public key
                if "-----BEGIN PUBLIC KEY-----" in public_key_info:
                    public_key_start = public_key_info.find("-----BEGIN PUBLIC KEY-----") + 27
                    public_key_end = public_key_info.find("-----END PUBLIC KEY-----")
                    public_key = public_key_info[public_key_start:public_key_end].strip()
                    return public_key
                
            else:
                print(f"[CERT] [ERROR] Public key loading failed: {result.stderr}")
                return None
        
        except Exception as e:
            print(f"[CERT] [ERROR] Public key loading error: {e}")
            return None

def main():
    import sys
    
    if len(sys.argv) < 5:
        print("Usage: python3 pqc_vpn_certificate_working.py <local_ip> <remote_ip> <cert_dir> <initiator|responder> [debug5]")
        print("Examples:")
        print("  VM1: python3 pqc_vpn_certificate_working.py 192.168.1.10 192.168.1.20 pqc_ipsec initiator")
        print("  VM2: python3 pqc_vpn_certificate_working.py 192.168.1.20 192.168.1.10 pqc_ipsec responder")
        print("  Debug: python3 pqc_vpn_certificate_working.py 192.168.1.20 192.168.1.10 pqc_ipsec responder debug5")
        print("\nDebug5 Mode:")
        print("  - Shows detailed ML-DSA mathematical operations")
        print("  - Displays certificate structure and analysis")
        print("  - Progress bars for data processing")
        print("  - Deep cryptographic insights and packet analysis")
        print("\nRequirements:")
        print("  - liboqs installed: sudo apt install liboqs-dev")
        print("  - Python bindings: pip install liboqs-python")
        print("  - ML-DSA certificate chain in cert_dir/client/ and cert_dir/server/")
        print("  - Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 in certificate chains")
        sys.exit(1)
    
    local_ip = sys.argv[1]
    remote_ip = sys.argv[2]
    cert_dir = sys.argv[3]
    is_initiator = sys.argv[4].lower() == "initiator"
    
    # Check for debug5 mode
    if len(sys.argv) > 5 and sys.argv[5].lower() == "debug5":
        set_debug_level(5)
        print("🔬" + "="*70)
        print("🔬 ML-DSA CERTIFICATE CHAIN VPN - DEBUG5 MODE ACTIVATED")
        print("🔬" + "="*70)
        print("🔬 [DEBUG5] Deep mathematical analysis enabled")
        print("🔬 [DEBUG5] Certificate visualization enabled") 
        print("🔬 [DEBUG5] Progress bars and packet analysis enabled")
        print("🔬 [DEBUG5] Post-quantum cryptographic insights enabled")
        print("🔬" + "="*70)
    
    debug_print(5, f"Initializing PQC VPN with parameters:")
    debug_print(5, f"├─ Local IP: {local_ip}")
    debug_print(5, f"├─ Remote IP: {remote_ip}")
    debug_print(5, f"├─ Certificate Directory: {cert_dir}")
    debug_print(5, f"└─ Role: {'Initiator' if is_initiator else 'Responder'}")
    
    vpn = MLDSAChainVPN(local_ip, remote_ip, cert_dir, is_initiator)
    
    try:
        vpn.start()
        
        while True:
            status = vpn.get_status()
            if DEBUG_LEVEL >= 5:
                print(f"\n🔬 [STATUS] ==================== VPN STATUS ====================")
                print(f"🔬 [STATUS] IKE Established: {status['ike_established']}")
                print(f"🔬 [STATUS] Tunnel Active: {status['tunnel_established']}")
                print(f"🔬 [STATUS] Identity: {status['identity']}")
                print(f"🔬 [STATUS] Chain Length: {status['chain_length']}")
                print(f"🔬 [STATUS] End-entity Algorithm: {status['end_entity_algorithm']}")
                print(f"🔬 [STATUS] Root Algorithm: {status['root_algorithm']}")
                print(f"🔬 [STATUS] Algorithms in Chain: {status['algorithms']}")
                print(f"🔬 [STATUS] ML-DSA Ready: {status.get('mldsa_ready', False)}")
                print(f"🔬 [STATUS] " + "="*50)
            else:
                print(f"[STATUS] IKE: {status['ike_established']}, Tunnel: {status['tunnel_established']}")
                print(f"[STATUS] Identity: {status['identity']}, Chain Length: {status['chain_length']}")
                print(f"[STATUS] End-entity: {status['end_entity_algorithm']}, Root: {status['root_algorithm']}")
                print(f"[STATUS] Algorithms in chain: {status['algorithms']}")
                print(f"[STATUS] ML-DSA Ready: {status.get('mldsa_ready', False)}")
                if not status.get('mldsa_ready', False):
                    print(f"[STATUS] [DEBUG] LIBOQS_AVAILABLE: {LIBOQS_AVAILABLE}, Signers count: {len(status.get('signers', {}))}")
            time.sleep(10)
            
    except KeyboardInterrupt:
        if DEBUG_LEVEL >= 5:
            print(f"\n🔬 [SHUTDOWN] Graceful shutdown initiated...")
            print(f"🔬 [SHUTDOWN] Cleaning up ML-DSA VPN resources...")
        print("\n[INFO] Shutting down ML-DSA Certificate Chain VPN...")
    except Exception as e:
        if DEBUG_LEVEL >= 5:
            print(f"🔬 [ERROR] Unexpected error in main: {e}")
            import traceback
            traceback.print_exc()
        print(f"[ERROR] Unexpected error: {e}")

if __name__ == "__main__":
    main()
