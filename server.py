import os
import json
import socket
import time
import hashlib
from datetime import datetime
from typing import Dict, Optional, Tuple

# --- Simulated PQC Crypto Layer ---

def generate_pqc_key_pair(algorithm_name: str) -> Tuple[bytes, bytes]:
    print(f"[CRYPTO] Generating {algorithm_name} key pair...")
    return os.urandom(1024), os.urandom(2048)

def sign_with_ml_dsa(private_key: str, message_data: bytes) -> str:
    print("[CRYPTO] Creating ML-DSA signature...")
    hashed = hashlib.sha256(message_data).digest()
    # Simulated signature as a random hex string
    return os.urandom(64).hex()

def verify_ml_dsa_signature(public_key: str, message_data: str, signature: str) -> bool:
    print("[CRYPTO] Verifying ML-DSA signature...")
    # Always return True for educational purposes
    return bool(signature and public_key)

# --- IKEv2 Server Simulation ---

class IKEServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 5000, server_id: str = "server.pqc.vpn"):
        self.server_id = server_id
        self.host = host
        self.port = port
        self.responder_spi = os.urandom(8).hex()

        self.pqc_public_key: Optional[bytes] = None
        self.pqc_private_key: Optional[bytes] = None

        self.server_certificate: Optional[str] = None
        self.ml_dsa_private_key: Optional[str] = None
        self.ca_certificate: Optional[str] = None
        self.intermediate_certificate: Optional[str] = None

    def load_credentials(self, server_cert_path: str, server_key_path: str, ca_cert_path: str, intermediate_cert_path: str):
        print("[INIT] Loading credentials...")
        try:
            with open(server_cert_path, 'r') as f:
                self.server_certificate = f.read()
            with open(server_key_path, 'r') as f:
                self.ml_dsa_private_key = f.read()
            with open(ca_cert_path, 'r') as f:
                self.ca_certificate = f.read()
            with open(intermediate_cert_path, 'r') as f:
                self.intermediate_certificate = f.read()
            print("[INIT] Credentials loaded successfully.")
        except FileNotFoundError as e:
            print(f"[ERROR] Credential file missing: {e}")
            exit(1)

    def handle_ike_sa_init(self, client_message: Dict) -> Dict:
        print(f"[{datetime.now()}] Handling IKE_SA_INIT...")
        client_pubkey = bytes.fromhex(client_message["payloads"][1]["key_exchange_data"])

        self.pqc_public_key, self.pqc_private_key = generate_pqc_key_pair("ML-KEM-768")

        response = {
            "header": {
                "initiator_spi": client_message["header"]["initiator_spi"],
                "responder_spi": self.responder_spi,
                "exchange_type": "IKE_SA_INIT"
            },
            "payloads": [
                client_message["payloads"][0],  # Copy SA
                {
                    "type": "KE",
                    "dh_group_id": 31,
                    "key_exchange_data": self.pqc_public_key.hex()
                }
            ]
        }
        return response

    def handle_ike_auth(self, client_message: Dict) -> Optional[Dict]:
        print(f"[{datetime.now()}] Handling IKE_AUTH...")

        client_cert = client_message["payloads"][0]["certificate"]
        client_signature = client_message["payloads"][1]["signature"]

        if verify_ml_dsa_signature(client_cert, "auth_payload", client_signature):
            print("[AUTH] Client authenticated successfully.")

            message_to_sign = json.dumps({
                "identity": self.server_id,
                "cert": self.server_certificate,
                "timestamp": str(datetime.utcnow())
            }).encode('utf-8')

            server_signature = sign_with_ml_dsa(self.ml_dsa_private_key, message_to_sign)

            return {
                "header": {
                    "initiator_spi": client_message["header"]["initiator_spi"],
                    "responder_spi": self.responder_spi,
                    "exchange_type": "IKE_AUTH"
                },
                "payloads": [
                    {"type": "CERT", "certificate": self.server_certificate},
                    {"type": "AUTH", "auth_method": "AUTH_METHOD_PKI", "signature": server_signature}
                ]
            }
        else:
            print("[AUTH] Client authentication failed.")
            return None

    def handle_child_sa(self, client_message: Dict) -> Dict:
        print(f"[{datetime.now()}] Handling CREATE_CHILD_SA...")

        return {
            "header": client_message["header"],
            "payloads": client_message["payloads"]
        }

    def start_simulation(self):
        print(f"\n[SERVER] Starting PQC IKEv2 Simulation at {self.host}:{self.port}")
        print("[SIMULATION] Awaiting client IKE_SA_INIT...")

        # --- Simulated Client Message Exchange ---
        time.sleep(1)
        client_init = {
            "header": {
                "initiator_spi": os.urandom(8).hex(),
                "responder_spi": "00",
                "exchange_type": "IKE_SA_INIT"
            },
            "payloads": [
                {
                    "type": "SA",
                    "proposals": [{
                        "proposal_number": 1,
                        "dh_group_id": 31,
                        "algorithms": {
                            "encryption": "AES_GCM_128",
                            "integrity": "SHA2_256",
                            "prf": "SHA2_256",
                            "key_exchange_group": "ML-KEM-768"
                        }
                    }]
                },
                {
                    "type": "KE",
                    "dh_group_id": 31,
                    "key_exchange_data": os.urandom(1024).hex()
                }
            ]
        }
        sa_init_response = self.handle_ike_sa_init(client_init)
        print(f"[RESPONSE] IKE_SA_INIT -> {json.dumps(sa_init_response, indent=2)}")

        time.sleep(1)
        print("\n[SIMULATION] Awaiting IKE_AUTH...")
        client_auth = {
            "header": sa_init_response["header"],
            "payloads": [
                {"type": "CERT", "certificate": "MOCK_CLIENT_CERT"},
                {"type": "AUTH", "auth_method": "AUTH_METHOD_PKI", "signature": "mock_signature"}
            ]
        }
        auth_response = self.handle_ike_auth(client_auth)
        if auth_response:
            print(f"[RESPONSE] IKE_AUTH -> {json.dumps(auth_response, indent=2)}")

        time.sleep(1)
        print("\n[SIMULATION] Awaiting CREATE_CHILD_SA...")
        client_child_sa = {
            "header": sa_init_response["header"],
            "payloads": [
                {
                    "type": "SA",
                    "proposals": [{
                        "proposal_number": 1,
                        "algorithms": {
                            "encryption": "AES_GCM_128",
                            "integrity": "SHA2_256"
                        }
                    }]
                },
                {"type": "TS_I", "traffic_selectors": ["192.168.1.10/32"]},
                {"type": "TS_R", "traffic_selectors": ["192.168.1.0/24"]}
            ]
        }
        child_sa_response = self.handle_child_sa(client_child_sa)
        print(f"[RESPONSE] CHILD_SA -> {json.dumps(child_sa_response, indent=2)}")

        print("\n[INFO] IKEv2 handshake simulation complete.")

# --- MAIN ---
if __name__ == "__main__":
    server = IKEServer()
    server.load_credentials(
        server_cert_path="server.cert.pem",
        server_key_path="server.key.pem",
        ca_cert_path="ca.crt.pem",
        intermediate_cert_path="intermediate.crt.pem"
    )
    server.start_simulation()
