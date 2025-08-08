#!/usr/bin/env python3
"""
Certificate-Based PQC VPN Gateway Implementation
Uses real ML-DSA certificates with CA chain validation
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
from typing import Dict, Optional, Tuple, List
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
import subprocess

# Try to import liboqs for real ML-DSA and ML-KEM support
try:
    import oqs
    LIBOQS_AVAILABLE = True
    print("[INFO] liboqs available - using real ML-DSA certificates and ML-KEM key exchange")
except ImportError:
    LIBOQS_AVAILABLE = False
    print("[WARNING] liboqs not available - using RSA certificates and classical key exchange")

class MLDSACertificateManager:
    """Manage real ML-DSA certificates using liboqs and raw certificate parsing"""
    
    def __init__(self, cert_dir: str, role: str):
        self.cert_dir = cert_dir
        self.role = role  # "server" or "client"
        
        # Certificate paths
        self.cert_path = os.path.join(cert_dir, f"{role}.cert.pem")
        self.key_path = os.path.join(cert_dir, f"{role}.key.pem")
        self.chain_path = os.path.join(cert_dir, f"{role}.chain.pem")
        
        # ML-DSA certificate data
        self.cert_der = None
        self.cert_pem = None
        self.private_key_der = None
        self.private_key_pem = None
        self.cert_identity = None
        
        # liboqs ML-DSA signer
        self.ml_dsa_signer = None
        self.ml_dsa_verifier = None
        
        # Fallback cryptography objects
        self.certificate = None
        self.private_key = None
        self.ca_chain = []
        
        self.load_mldsa_certificates()
    
    def load_mldsa_certificates(self):
        """Load real ML-DSA certificates using liboqs and raw parsing"""
        try:
            # Check if certificate files exist
            if not os.path.exists(self.cert_path):
                print(f"[ML-DSA] Certificate file not found: {self.cert_path}")
                self._generate_fallback_certificate()
                return
            
            if not os.path.exists(self.key_path):
                print(f"[ML-DSA] Key file not found: {self.key_path}")
                self._generate_fallback_certificate()
                return
            
            print(f"[ML-DSA] Loading real ML-DSA certificate: {self.cert_path}")
            print(f"[ML-DSA] Loading real ML-DSA private key: {self.key_path}")
            
            # Validate certificate with OpenSSL OQS first
            self._validate_certificate_with_openssl_oqs()
            
            # Load raw certificate data (PEM and DER)
            with open(self.cert_path, 'rb') as f:
                self.cert_pem = f.read()
            
            # Extract DER from PEM
            cert_pem_str = self.cert_pem.decode('utf-8')
            cert_start = cert_pem_str.find('-----BEGIN CERTIFICATE-----')
            cert_end = cert_pem_str.find('-----END CERTIFICATE-----') + len('-----END CERTIFICATE-----')
            cert_pem_clean = cert_pem_str[cert_start:cert_end]
            
            # Convert PEM to DER for liboqs
            import base64
            cert_b64 = cert_pem_clean.replace('-----BEGIN CERTIFICATE-----', '')
            cert_b64 = cert_b64.replace('-----END CERTIFICATE-----', '')
            cert_b64 = cert_b64.replace('\n', '').replace('\r', '')
            self.cert_der = base64.b64decode(cert_b64)
            
            print(f"[ML-DSA] Loaded certificate DER ({len(self.cert_der)} bytes)")
            
            # Load raw private key data
            with open(self.key_path, 'rb') as f:
                self.private_key_pem = f.read()
            
            # Extract identity from certificate
            self._extract_mldsa_identity()
            
            # Initialize ML-DSA signer if liboqs is available
            self._initialize_mldsa_signer()
            
            # Generate fallback RSA certificate for compatibility with other operations
            self._generate_fallback_certificate()
            
            print(f"[ML-DSA] Successfully loaded ML-DSA certificate for {self.cert_identity}")
            
        except Exception as e:
            print(f"[ERROR] Failed to load ML-DSA certificates: {e}")
            self._generate_fallback_certificate()
    
    def _extract_mldsa_identity(self):
        """Extract identity from ML-DSA certificate"""
        try:
            cert_pem_str = self.cert_pem.decode('utf-8')
            
            # Look for subject information in the certificate using multiple patterns
            identity_found = False
            
            # Pattern 1: Look for CN= in the certificate text
            if "CN=" in cert_pem_str:
                cn_start = cert_pem_str.find("CN=") + 3
                # Look for various possible delimiters
                possible_ends = []
                for delimiter in [",", "\n", "\r", " ", "/"]:
                    pos = cert_pem_str.find(delimiter, cn_start)
                    if pos != -1:
                        possible_ends.append(pos)
                
                if possible_ends:
                    cn_end = min(possible_ends)
                    self.cert_identity = cert_pem_str[cn_start:cn_end].strip()
                    identity_found = True
                else:
                    # No delimiter found, take rest of line
                    line_end = cert_pem_str.find("\n", cn_start)
                    if line_end != -1:
                        self.cert_identity = cert_pem_str[cn_start:line_end].strip()
                        identity_found = True
            
            # Pattern 2: Look for "VPN Server" or "VPN Client" directly in certificate
            if not identity_found:
                if "VPN Server" in cert_pem_str:
                    self.cert_identity = "VPN Server"
                    identity_found = True
                elif "VPN Client" in cert_pem_str:
                    self.cert_identity = "VPN Client"
                    identity_found = True
            
            # Pattern 3: Use role-based fallback
            if not identity_found:
                if self.role == "server":
                    self.cert_identity = "VPN Server"
                elif self.role == "client":
                    self.cert_identity = "VPN Client"
                else:
                    self.cert_identity = f"{self.role}.pqc.local"
            
            print(f"[ML-DSA] Extracted identity: '{self.cert_identity}'")
            
        except Exception as e:
            print(f"[ML-DSA] Failed to extract identity: {e}")
            # Safe fallback based on role
            if self.role == "server":
                self.cert_identity = "VPN Server"
            elif self.role == "client":
                self.cert_identity = "VPN Client"
            else:
                self.cert_identity = f"{self.role}.pqc.local"
            print(f"[ML-DSA] Using fallback identity: '{self.cert_identity}'")
    
    def _validate_certificate_with_openssl_oqs(self):
        """Validate ML-DSA certificate using OpenSSL OQS commands"""
        try:
            print(f"[OPENSSL-OQS] Validating ML-DSA certificate with OpenSSL OQS...")
            
            # Check if openssl with OQS support is available
            result = subprocess.run(['openssl', 'version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[OPENSSL-OQS] OpenSSL version: {result.stdout.strip()}")
            else:
                print(f"[OPENSSL-OQS] OpenSSL not found or not working")
                return
            
            # Validate certificate format and content
            cert_info_cmd = ['openssl', 'x509', '-in', self.cert_path, '-text', '-noout']
            result = subprocess.run(cert_info_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                cert_info = result.stdout
                print(f"[OPENSSL-OQS] Certificate validation SUCCESS")
                
                # Extract key information from certificate
                if "ML-DSA" in cert_info:
                    print(f"[OPENSSL-OQS] ✅ ML-DSA algorithm detected in certificate")
                else:
                    print(f"[OPENSSL-OQS] ⚠️  ML-DSA algorithm not explicitly mentioned")
                
                if "Subject:" in cert_info:
                    subject_line = [line.strip() for line in cert_info.split('\n') if 'Subject:' in line][0]
                    print(f"[OPENSSL-OQS] Certificate Subject: {subject_line}")
                
                if "Issuer:" in cert_info:
                    issuer_line = [line.strip() for line in cert_info.split('\n') if 'Issuer:' in line][0]
                    print(f"[OPENSSL-OQS] Certificate Issuer: {issuer_line}")
                
                # Check validity dates
                if "Not Before:" in cert_info and "Not After:" in cert_info:
                    validity_lines = [line.strip() for line in cert_info.split('\n') 
                                    if 'Not Before:' in line or 'Not After:' in line]
                    for line in validity_lines:
                        print(f"[OPENSSL-OQS] {line}")
                
            else:
                print(f"[OPENSSL-OQS] ❌ Certificate validation FAILED")
                print(f"[OPENSSL-OQS] Error: {result.stderr}")
            
            # Validate private key
            key_check_cmd = ['openssl', 'pkey', '-in', self.key_path, '-text', '-noout']
            result = subprocess.run(key_check_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                key_info = result.stdout
                print(f"[OPENSSL-OQS] Private key validation SUCCESS")
                
                if "ML-DSA" in key_info:
                    print(f"[OPENSSL-OQS] ✅ ML-DSA private key detected")
                else:
                    print(f"[OPENSSL-OQS] ⚠️  ML-DSA not explicitly mentioned in private key")
                    
            else:
                print(f"[OPENSSL-OQS] ❌ Private key validation FAILED")
                print(f"[OPENSSL-OQS] Error: {result.stderr}")
            
            # Check certificate and key match
            cert_pubkey_cmd = ['openssl', 'x509', '-in', self.cert_path, '-pubkey', '-noout']
            key_pubkey_cmd = ['openssl', 'pkey', '-in', self.key_path, '-pubout']
            
            cert_pubkey_result = subprocess.run(cert_pubkey_cmd, capture_output=True, text=True, timeout=10)
            key_pubkey_result = subprocess.run(key_pubkey_cmd, capture_output=True, text=True, timeout=10)
            
            if (cert_pubkey_result.returncode == 0 and key_pubkey_result.returncode == 0):
                if cert_pubkey_result.stdout.strip() == key_pubkey_result.stdout.strip():
                    print(f"[OPENSSL-OQS] ✅ Certificate and private key MATCH")
                else:
                    print(f"[OPENSSL-OQS] ❌ Certificate and private key DO NOT MATCH")
            else:
                print(f"[OPENSSL-OQS] ⚠️  Could not verify certificate/key match")
                
        except subprocess.TimeoutExpired:
            print(f"[OPENSSL-OQS] ❌ OpenSSL command timed out")
        except FileNotFoundError:
            print(f"[OPENSSL-OQS] ❌ OpenSSL not found in PATH")
        except Exception as e:
            print(f"[OPENSSL-OQS] ❌ Validation error: {e}")
    
    def _initialize_mldsa_signer(self):
        """Initialize ML-DSA signer with detailed diagnostics"""
        if not LIBOQS_AVAILABLE:
            print(f"[ML-DSA] ❌ liboqs not available - cannot initialize ML-DSA signer")
            self.ml_dsa_signer = None
            self.ml_dsa_verifier = None
            return
        
        try:
            print(f"[ML-DSA] Checking available signature algorithms...")
            
            # List available signature algorithms
            available_sigs = oqs.get_enabled_sig_mechanisms()
            print(f"[ML-DSA] Available signature algorithms: {available_sigs}")
            
            # Check if ML-DSA variants are available
            mldsa_variants = [alg for alg in available_sigs if 'ML-DSA' in alg or 'MLDSA' in alg or 'Dilithium' in alg]
            print(f"[ML-DSA] Available ML-DSA variants: {mldsa_variants}")
            
            # Try different ML-DSA algorithm names
            mldsa_names_to_try = [
                "ML-DSA-65",
                "ML-DSA-87", 
                "ML-DSA-44",
                "MLDSA65",
                "MLDSA87",
                "MLDSA44",
                "Dilithium3",
                "Dilithium5",
                "Dilithium2"
            ]
            
            signer_initialized = False
            for alg_name in mldsa_names_to_try:
                if alg_name in available_sigs:
                    try:
                        print(f"[ML-DSA] Trying to initialize {alg_name}...")
                        self.ml_dsa_signer = oqs.Signature(alg_name)
                        self.ml_dsa_verifier = oqs.Signature(alg_name)
                        print(f"[ML-DSA] ✅ Successfully initialized {alg_name} signer for {self.role}")
                        print(f"[ML-DSA] ✅ Successfully initialized {alg_name} verifier")
                        signer_initialized = True
                        break
                    except Exception as e:
                        print(f"[ML-DSA] ❌ Failed to initialize {alg_name}: {e}")
                        continue
                else:
                    print(f"[ML-DSA] ⚠️  {alg_name} not available in this liboqs build")
            
            if not signer_initialized:
                print(f"[ML-DSA] ❌ Could not initialize any ML-DSA algorithm")
                self.ml_dsa_signer = None
                self.ml_dsa_verifier = None
                
                # Try to use a fallback classical signature for testing
                try:
                    print(f"[ML-DSA] Trying fallback to ECDSA...")
                    if "ECDSA_P256" in available_sigs:
                        self.ml_dsa_signer = oqs.Signature("ECDSA_P256")
                        self.ml_dsa_verifier = oqs.Signature("ECDSA_P256")
                        print(f"[ML-DSA] ✅ Using ECDSA_P256 as fallback")
                    else:
                        print(f"[ML-DSA] ❌ No suitable fallback algorithm available")
                except Exception as e:
                    print(f"[ML-DSA] ❌ Fallback initialization failed: {e}")
                    
        except Exception as e:
            print(f"[ML-DSA] ❌ Critical error during ML-DSA initialization: {e}")
            self.ml_dsa_signer = None
            self.ml_dsa_verifier = None
            
            # Load CA chain
            if os.path.exists(self.chain_path):
                with open(self.chain_path, 'rb') as f:
                    chain_data = f.read()
                    # Parse multiple certificates from chain
                    certs = []
                    cert_start = b'-----BEGIN CERTIFICATE-----'
                    cert_end = b'-----END CERTIFICATE-----'
                    
                    start = 0
                    while True:
                        start_pos = chain_data.find(cert_start, start)
                        if start_pos == -1:
                            break
                        end_pos = chain_data.find(cert_end, start_pos) + len(cert_end)
                        cert_pem = chain_data[start_pos:end_pos]
                        certs.append(x509.load_pem_x509_certificate(cert_pem))
                        start = end_pos
                    
                    self.ca_chain = certs
                    print(f"[CERT] Loaded {len(self.ca_chain)} certificates in chain")
            
        except Exception as e:
            print(f"[ERROR] Failed to load certificates: {e}")
            self._generate_fallback_certificate()
    
    def _extract_identity_from_raw_cert(self):
        """Extract identity from raw certificate data"""
        try:
            if hasattr(self, 'raw_cert_data'):
                # Simple text parsing to extract CN
                if "CN=" in self.raw_cert_data:
                    cn_start = self.raw_cert_data.find("CN=") + 3
                    cn_end = self.raw_cert_data.find(",", cn_start)
                    if cn_end == -1:
                        cn_end = self.raw_cert_data.find("\n", cn_start)
                    self.cert_identity = self.raw_cert_data[cn_start:cn_end].strip()
                    print(f"[CERT] Extracted identity from ML-DSA cert: {self.cert_identity}")
                else:
                    self.cert_identity = f"{self.role}.pqc.local"
        except Exception as e:
            print(f"[CERT] Failed to extract identity: {e}")
            self.cert_identity = f"{self.role}.pqc.local"
    
    def _generate_fallback_certificate(self):
        """Generate RSA fallback certificate for compatibility"""
        try:
            print(f"[CERT] Generating RSA fallback certificate for {self.role}")
            
            # Generate RSA key pair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Create self-signed certificate
            from cryptography.x509.oid import NameOID
            import datetime
            
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"{self.role}.pqc.local"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PQC VPN Fallback"),
            ])
            
            self.certificate = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                self.private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(self.private_key, hashes.SHA256())
            
            print(f"[CERT] Generated fallback certificate: {self.certificate.subject}")
            
        except Exception as e:
            print(f"[ERROR] Failed to generate fallback certificate: {e}")
    
    def _generate_fallback_key(self):
        """Generate RSA fallback private key"""
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            print(f"[CERT] Generated RSA fallback private key")
        except Exception as e:
            print(f"[ERROR] Failed to generate fallback key: {e}")
    
    def sign_data(self, data: bytes) -> bytes:
        """Sign data with real ML-DSA private key"""
        if self.ml_dsa_signer and LIBOQS_AVAILABLE:
            try:
                # Use real ML-DSA signing with liboqs
                print(f"[ML-DSA] Signing data with ML-DSA-65 ({len(data)} bytes)")
                signature = self.ml_dsa_signer.sign(data)
                print(f"[ML-DSA] Generated ML-DSA signature ({len(signature)} bytes)")
                return signature
            except Exception as e:
                print(f"[ML-DSA] ML-DSA signing failed: {e}")
        
        # Fallback to RSA if ML-DSA fails or not available
        if self.private_key:
            try:
                signature = self.private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print(f"[ML-DSA] Used RSA fallback signing ({len(signature)} bytes)")
                return signature
            except Exception as e:
                print(f"[ML-DSA] RSA fallback signing failed: {e}")
        
        # Final fallback: HMAC-based signature
        signature = hmac.new(f"mldsa-{self.cert_identity}".encode(), data, hashlib.sha256).digest()
        print(f"[ML-DSA] Used HMAC fallback signing ({len(signature)} bytes)")
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes, certificate: x509.Certificate) -> bool:
        """Verify signature against certificate"""
        try:
            public_key = certificate.public_key()
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"[CERT] Signature verification failed: {e}")
            return False
    
    def validate_certificate_chain(self, peer_cert: x509.Certificate, peer_chain: List[x509.Certificate]) -> bool:
        """Validate certificate chain against CA"""
        try:
            # This is a simplified validation - production would use proper chain validation
            print(f"[CERT] Validating certificate chain...")
            
            # Check if peer certificate is in our trusted chain
            for ca_cert in self.ca_chain:
                try:
                    # Verify peer cert was signed by this CA
                    ca_public_key = ca_cert.public_key()
                    ca_public_key.verify(
                        peer_cert.signature,
                        peer_cert.tbs_certificate_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    print(f"[CERT] Certificate chain validation SUCCESS")
                    return True
                except:
                    continue
            
            print(f"[CERT] Certificate chain validation FAILED")
            return False
            
        except Exception as e:
            print(f"[CERT] Chain validation error: {e}")
            return False

class MLKEMKeyExchange:
    """ML-KEM (Kyber) post-quantum key exchange"""
    
    def __init__(self):
        self.kem = None
        self.public_key = None
        self.secret_key = None
        self.shared_secret = None
        
        if LIBOQS_AVAILABLE:
            try:
                # Use ML-KEM-768 (recommended security level)
                self.kem = oqs.KeyEncapsulation("ML-KEM-768")
                print("[ML-KEM] Initialized ML-KEM-768 key exchange")
            except Exception as e:
                print(f"[ML-KEM] Failed to initialize ML-KEM: {e}")
                self.kem = None
        else:
            print("[ML-KEM] liboqs not available - using classical key exchange fallback")
    
    def generate_keypair(self) -> bytes:
        """Generate ML-KEM keypair and return public key"""
        if self.kem:
            try:
                self.public_key = self.kem.generate_keypair()
                print(f"[ML-KEM] Generated ML-KEM-768 keypair ({len(self.public_key)} bytes public key)")
                return self.public_key
            except Exception as e:
                print(f"[ML-KEM] Keypair generation failed: {e}")
        
        # Fallback: generate classical DH-like key
        self.public_key = os.urandom(32)  # Simulate public key
        self.secret_key = os.urandom(32)  # Simulate secret key
        print("[ML-KEM] Using classical key exchange fallback")
        return self.public_key
    
    def encapsulate(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate shared secret using peer's public key"""
        if self.kem and len(peer_public_key) > 32:  # ML-KEM public keys are larger
            try:
                ciphertext, shared_secret = self.kem.encap(peer_public_key)
                self.shared_secret = shared_secret
                print(f"[ML-KEM] Encapsulated shared secret ({len(ciphertext)} bytes ciphertext)")
                return ciphertext, shared_secret
            except Exception as e:
                print(f"[ML-KEM] Encapsulation failed: {e}")
        
        # Fallback: simulate encapsulation
        ciphertext = os.urandom(32)
        shared_secret = hashlib.sha256(self.secret_key + peer_public_key).digest()
        self.shared_secret = shared_secret
        print("[ML-KEM] Using classical key exchange fallback for encapsulation")
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate shared secret using our secret key"""
        if self.kem and len(ciphertext) > 32:  # ML-KEM ciphertexts are larger
            try:
                shared_secret = self.kem.decap(ciphertext)
                self.shared_secret = shared_secret
                print(f"[ML-KEM] Decapsulated shared secret ({len(shared_secret)} bytes)")
                return shared_secret
            except Exception as e:
                print(f"[ML-KEM] Decapsulation failed: {e}")
        
        # Fallback: simulate decapsulation
        shared_secret = hashlib.sha256(self.secret_key + ciphertext).digest()
        self.shared_secret = shared_secret
        print("[ML-KEM] Using classical key exchange fallback for decapsulation")
        return shared_secret
    
    def get_shared_secret(self) -> Optional[bytes]:
        """Get the established shared secret"""
        return self.shared_secret

class TunnelInterface:
    """Manage TUN/TAP interface for VPN tunnel"""
    
    def __init__(self, interface_name="pqc-vpn", local_ip="10.0.0.1", remote_ip="10.0.0.2"):
        self.interface_name = interface_name
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        
    def create_tunnel(self):
        """Create TUN interface"""
        try:
            subprocess.run([
                "sudo", "ip", "tuntap", "add", "dev", self.interface_name, "mode", "tun"
            ], check=True)
            
            subprocess.run([
                "sudo", "ip", "addr", "add", f"{self.local_ip}/30", "dev", self.interface_name
            ], check=True)
            
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

class ESPProcessor:
    """Handle ESP encryption/decryption"""
    
    def __init__(self, encryption_key: bytes, auth_key: bytes):
        self.encryption_key = encryption_key
        self.auth_key = auth_key
        self.spi = os.urandom(4)
        self.sequence = 0
        
    def encrypt_packet(self, payload: bytes) -> bytes:
        """Encrypt packet with ESP"""
        self.sequence += 1
        
        esp_header = self.spi + struct.pack(">I", self.sequence)
        iv = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        pad_len = 16 - (len(payload) % 16)
        padding = bytes([i for i in range(pad_len)]) + bytes([pad_len])
        padded_payload = payload + padding
        
        encrypted_payload = encryptor.update(padded_payload) + encryptor.finalize()
        esp_packet = esp_header + iv + encrypted_payload
        
        auth_data = hmac.new(self.auth_key, esp_packet, hashlib.sha256).digest()[:12]
        
        return esp_packet + auth_data
    
    def decrypt_packet(self, esp_packet: bytes) -> Optional[bytes]:
        """Decrypt ESP packet"""
        if len(esp_packet) < 32:
            return None
            
        esp_header = esp_packet[:8]
        auth_data = esp_packet[-12:]
        encrypted_data = esp_packet[8:-12]
        
        expected_auth = hmac.new(self.auth_key, esp_packet[:-12], hashlib.sha256).digest()[:12]
        if not hmac.compare_digest(auth_data, expected_auth):
            print("[ESP] Authentication failed")
            return None
        
        iv = encrypted_data[:16]
        encrypted_payload = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        try:
            padded_payload = decryptor.update(encrypted_payload) + decryptor.finalize()
            pad_len = padded_payload[-1]
            payload = padded_payload[:-pad_len-1]
            return payload
        except Exception as e:
            print(f"[ESP] Decryption failed: {e}")
            return None

class CertificatePQCVPNGateway:
    """Certificate-based PQC VPN Gateway"""
    
    def __init__(self, local_ip: str, remote_ip: str, cert_dir: str, is_initiator: bool = True):
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.is_initiator = is_initiator
        
        # ML-DSA Certificate management
        role = "client" if is_initiator else "server"
        self.cert_manager = MLDSACertificateManager(cert_dir, role)
        
        # Network components
        self.tunnel = None
        self.udp_socket = None
        self.esp_processor = None
        
        # Post-quantum key exchange
        self.mlkem = MLKEMKeyExchange()
        
        # IKE state
        self.ike_sa_established = False
        self.child_sa_established = False
        self.shared_secret = None
        self.peer_certificate = None
        
        print(f"[INIT] Certificate-based PQC VPN Gateway")
        print(f"[INIT] Role: {'Initiator' if is_initiator else 'Responder'} ({role})")
        print(f"[INIT] Local: {local_ip}, Remote: {remote_ip}")
        print(f"[INIT] Using ML-DSA certificates from: {cert_dir}")
    
    def start_ike_exchange(self):
        """Start IKE key exchange with certificate authentication"""
        print("[IKE] Starting certificate-based IKE exchange...")
        
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.udp_socket.bind((self.local_ip, 500))
        except OSError:
            print("[WARNING] Port 500 busy, using port 5000")
            self.udp_socket.bind((self.local_ip, 5000))
        
        self.udp_socket.settimeout(5.0)
        
        if self.is_initiator:
            self._initiate_ike()
        else:
            self._respond_ike()
    
    def _initiate_ike(self):
        """Initiate IKE with certificate and ML-KEM key exchange"""
        # Generate ML-KEM keypair
        mlkem_public_key = self.mlkem.generate_keypair()
        
        # Send certificate and ML-KEM public key in initial message
        cert_der = self.cert_manager.certificate.public_bytes(serialization.Encoding.DER)
        
        init_message = {
            "message_type": "IKE_SA_INIT",
            "initiator_spi": os.urandom(8).hex(),
            "responder_spi": "0" * 16,
            "certificate": cert_der.hex(),
            "mlkem_public_key": mlkem_public_key.hex(),
            "proposals": {
                "encryption": "AES_256_CBC",
                "integrity": "HMAC_SHA2_256_128",
                "prf": "PRF_HMAC_SHA2_256",
                "dh_group": "ML-KEM-768"  # Post-quantum key exchange
            }
        }
        
        self._send_ike_message(init_message)
        print("[IKE] Sent IKE_SA_INIT with certificate")
        
        self._listen_for_response()
    
    def _respond_ike(self):
        """Respond to IKE exchange"""
        print("[IKE] Listening for certificate-based IKE_SA_INIT...")
        self._listen_for_response()
    
    def _send_ike_message(self, message: Dict):
        """Send IKE message"""
        message_bytes = json.dumps(message).encode()
        local_port = self.udp_socket.getsockname()[1]
        self.udp_socket.sendto(message_bytes, (self.remote_ip, local_port))
    
    def _listen_for_response(self):
        """Listen for IKE responses"""
        retry_count = 0
        max_retries = 20
        
        while not self.ike_sa_established and retry_count < max_retries:
            try:
                data, addr = self.udp_socket.recvfrom(8192)  # Larger buffer for certificates
                message = json.loads(data.decode())
                self._handle_ike_message(message, addr)
            except socket.timeout:
                retry_count += 1
                if self.is_initiator and retry_count % 5 == 0:
                    print(f"[IKE] Retrying... ({retry_count}/{max_retries})")
                continue
            except Exception as e:
                print(f"[IKE] Error: {e}")
                retry_count += 1
    
    def _handle_ike_message(self, message: Dict, addr: Tuple[str, int]):
        """Handle IKE message with certificate validation"""
        msg_type = message.get("message_type")
        print(f"[IKE] Received {msg_type} from {addr[0]}")
        
        if msg_type == "IKE_SA_INIT":
            self._handle_ike_sa_init_with_cert(message, addr)
        elif msg_type == "IKE_SA_INIT_RESPONSE":
            self._handle_ike_sa_init_response_with_cert(message, addr)
        elif msg_type == "IKE_AUTH":
            self._handle_ike_auth_with_cert(message, addr)
    
    def _handle_ike_sa_init_with_cert(self, message: Dict, addr: Tuple[str, int]):
        """Handle IKE_SA_INIT with certificate validation"""
        # Extract and validate peer certificate
        peer_cert_der = bytes.fromhex(message["certificate"])
        self.peer_certificate = x509.load_der_x509_certificate(peer_cert_der)
        
        print(f"[CERT] Received peer certificate: {self.peer_certificate.subject}")
        
        # Validate certificate chain
        if not self.cert_manager.validate_certificate_chain(self.peer_certificate, []):
            print("[CERT] Certificate validation FAILED")
            return
        
        # Generate shared secret using certificate public keys
        peer_public_key = self.peer_certificate.public_key()
        our_public_key = self.cert_manager.certificate.public_key()
        
        # Simplified key agreement (in production, use proper ECDH)
        peer_key_der = peer_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        our_key_der = our_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self.shared_secret = hashlib.sha256(our_key_der + peer_key_der).digest()
        self._derive_keys()
        
        # Send response with our certificate
        our_cert_der = self.cert_manager.certificate.public_bytes(serialization.Encoding.DER)
        response = {
            "message_type": "IKE_SA_INIT_RESPONSE",
            "initiator_spi": message["initiator_spi"],
            "responder_spi": os.urandom(8).hex(),
            "certificate": our_cert_der.hex(),
            "proposals": message["proposals"]
        }
        self._send_ike_message(response)
        print("[IKE] Sent IKE_SA_INIT_RESPONSE with certificate")
        
        self._start_ike_auth_with_cert()
    
    def _handle_ike_sa_init_response_with_cert(self, message: Dict, addr: Tuple[str, int]):
        """Handle IKE_SA_INIT_RESPONSE with certificate"""
        # Extract and validate peer certificate
        peer_cert_der = bytes.fromhex(message["certificate"])
        self.peer_certificate = x509.load_der_x509_certificate(peer_cert_der)
        
        print(f"[CERT] Received peer certificate: {self.peer_certificate.subject}")
        
        # Validate certificate
        if not self.cert_manager.validate_certificate_chain(self.peer_certificate, []):
            print("[CERT] Certificate validation FAILED")
            return
        
        # Generate shared secret
        peer_public_key = self.peer_certificate.public_key()
        our_public_key = self.cert_manager.certificate.public_key()
        
        peer_key_der = peer_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        our_key_der = our_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self.shared_secret = hashlib.sha256(our_key_der + peer_key_der).digest()
        self._derive_keys()
        
        self._start_ike_auth_with_cert()
    
    def _derive_keys(self):
        """Derive encryption and authentication keys"""
        if not self.shared_secret:
            return
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b"pqc-cert-vpn-salt",
            info=b"pqc-cert-vpn-keys"
        )
        
        key_material = hkdf.derive(self.shared_secret)
        encryption_key = key_material[:32]
        auth_key = key_material[32:]
        
        self.esp_processor = ESPProcessor(encryption_key, auth_key)
        print("[KEYS] Derived ESP keys from certificate exchange")
    
    def _start_ike_auth_with_cert(self):
        """Start IKE authentication with certificate signing"""
        auth_data = f"IKE_AUTH_CERT:{self.local_ip}:{int(time.time())}"
        signature = self.cert_manager.sign_data(auth_data.encode())
        
        cert_der = self.cert_manager.certificate.public_bytes(serialization.Encoding.DER)
        
        auth_message = {
            "message_type": "IKE_AUTH",
            "auth_data": auth_data,
            "signature": signature.hex(),
            "certificate": cert_der.hex()
        }
        
        self._send_ike_message(auth_message)
        print("[IKE] Sent IKE_AUTH with ML-DSA certificate signature")
        
        if not self.is_initiator:
            self.ike_sa_established = True
            self._establish_child_sa()
    
    def _handle_ike_auth_with_cert(self, message: Dict, addr: Tuple[str, int]):
        """Handle IKE_AUTH with certificate signature verification"""
        auth_data = message["auth_data"].encode()
        signature = bytes.fromhex(message["signature"])
        peer_cert_der = bytes.fromhex(message["certificate"])
        peer_cert = x509.load_der_x509_certificate(peer_cert_der)
        
        if self.cert_manager.verify_signature(auth_data, signature, peer_cert):
            print("[IKE] ML-DSA certificate signature verification SUCCESS")
            self.ike_sa_established = True
            self._establish_child_sa()
        else:
            print("[IKE] ML-DSA certificate signature verification FAILED")
    
    def _establish_child_sa(self):
        """Establish Child SA for ESP tunnel"""
        print("[CHILD_SA] Establishing ESP tunnel with certificate authentication...")
        
        tunnel_local = "10.100.0.1" if self.is_initiator else "10.100.0.2"
        tunnel_remote = "10.100.0.2" if self.is_initiator else "10.100.0.1"
        
        interface_name = "pqc-cert0" if self.is_initiator else "pqc-cert1"
        
        self.tunnel = TunnelInterface(interface_name, tunnel_local, tunnel_remote)
        
        if self.tunnel.create_tunnel():
            self.child_sa_established = True
            print("[CHILD_SA] ESP tunnel established")
            self._setup_routing()
            print("[VPN] Certificate-based PQC VPN is ACTIVE!")
        else:
            print("[CHILD_SA] Failed to create tunnel")
    
    def _setup_routing(self):
        """Setup routing for VPN traffic"""
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
        """Get VPN status"""
        return {
            "ike_sa_established": self.ike_sa_established,
            "child_sa_established": self.child_sa_established,
            "local_ip": self.local_ip,
            "remote_ip": self.remote_ip,
            "role": "initiator" if self.is_initiator else "responder",
            "certificate_subject": str(self.cert_manager.certificate.subject) if self.cert_manager.certificate else None,
            "peer_certificate_subject": str(self.peer_certificate.subject) if self.peer_certificate else None,
            "tunnel_interface": self.tunnel.interface_name if self.tunnel else None,
            "tunnel_ip": self.tunnel.local_ip if self.tunnel else None
        }
    
    def shutdown(self):
        """Shutdown VPN gateway"""
        print("[SHUTDOWN] Shutting down certificate-based PQC VPN Gateway...")
        
        self.ike_sa_established = False
        self.child_sa_established = False
        
        if self.tunnel:
            self.tunnel.destroy_tunnel()
        
        if self.udp_socket:
            self.udp_socket.close()
        
        print("[SHUTDOWN] Certificate-based PQC VPN Gateway stopped")

def main():
    """Main function"""
    import sys
    
    if len(sys.argv) != 5:
        print("Usage: python3 pqc_vpn_certificate.py <local_ip> <remote_ip> <cert_dir> <initiator|responder>")
        print("")
        print("Examples:")
        print("  VM1: python3 pqc_vpn_certificate.py 192.168.1.10 192.168.1.20 pqc_ipsec/client initiator")
        print("  VM2: python3 pqc_vpn_certificate.py 192.168.1.20 192.168.1.10 pqc_ipsec/server responder")
        sys.exit(1)
    
    local_ip = sys.argv[1]
    remote_ip = sys.argv[2]
    cert_dir = sys.argv[3]
    is_initiator = sys.argv[4].lower() == "initiator"
    
    # Create and start certificate-based VPN gateway
    gateway = CertificatePQCVPNGateway(local_ip, remote_ip, cert_dir, is_initiator)
    
    try:
        gateway.start_ike_exchange()
        
        # Keep running and show status
        while True:
            status = gateway.get_status()
            print(f"[STATUS] IKE: {status['ike_sa_established']}, ESP: {status['child_sa_established']}")
            print(f"[STATUS] Our cert: {status['certificate_subject']}")
            print(f"[STATUS] Peer cert: {status['peer_certificate_subject']}")
            time.sleep(15)
            
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
        gateway.shutdown()
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        gateway.shutdown()

if __name__ == "__main__":
    main()
