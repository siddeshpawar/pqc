import os
import json
import time
import hashlib
from datetime import datetime
from typing import Tuple, Dict

# --- Simulated PQC Crypto Layer ---

def generate_pqc_key_pair(algorithm_name: str) -> Tuple[bytes, bytes]:
    print(f"[CRYPTO] Client generating {algorithm_name} key pair...")
    return os.urandom(1024), os.urandom(2048)

def sign_with_ml_dsa(private_key: str, message_data: bytes) -> str:
    print("[CRYPTO] Client creating ML-DSA signature...")
    hashed = hashlib.sha256(message_data).digest()
    return os.urandom(64).hex()

def verify_server_signature(public_key: str, message: str, signature: str) -> bool:
    print("[CRYPTO] Client verifying server signature...")
    return bool(signature and public_key)

# --- IKEv2 Client Simulation ---

class IKEClient:
    def __init__(self, client_id: str = "client.pqc.vpn"):
        self.initiator_spi = os.urandom(8).hex()
        self.client_id = client_id

        self.pqc_public_key: bytes = b""
        self.pqc_private_key: bytes = b""
        self.server_certificate: str = ""
        self.ml_dsa_private_key: str = ""
        self.client_certificate: str = "MOCK_CLIENT_CERT"

    def load_credentials(self, client_key_path: str):
        print("[INIT] Loading client credentials...")
        try:
            with open(client_key_path, 'r') as f:
                self.ml_dsa_private_key = f.read()
            print("[INIT] Credentials loaded.")
        except FileNotFoundError as e:
            print(f"[ERROR] {e}")
            exit(1)

    def build_ike_sa_init(self) -> Dict:
        print(f"[{datetime.now()}] Client building IKE_SA_INIT...")
        self.pqc_public_key, self.pqc_private_key = generate_pqc_key_pair("ML-KEM-768")

        return {
            "header": {
                "initiator_spi": self.initiator_spi,
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
                    "key_exchange_data": self.pqc_public_key.hex()
                }
            ]
        }

    def build_ike_auth(self, server_id: str, server_cert: str) -> Dict:
        print(f"[{datetime.now()}] Client building IKE_AUTH...")

        auth_data = json.dumps({
            "identity": server_id,
            "certificate": server_cert,
            "timestamp": str(datetime.utcnow())
        }).encode('utf-8')

        signature = sign_with_ml_dsa(self.ml_dsa_private_key, auth_data)

        return {
            "header": {
                "initiator_spi": self.initiator_spi,
                "responder_spi": "SIMULATED_SERVER_SPI",  # This should be replaced after INIT response
                "exchange_type": "IKE_AUTH"
            },
            "payloads": [
                {"type": "CERT", "certificate": self.client_certificate},
                {"type": "AUTH", "auth_method": "AUTH_METHOD_PKI", "signature": signature}
            ]
        }

    def build_child_sa(self) -> Dict:
        print(f"[{datetime.now()}] Client building CREATE_CHILD_SA...")

        return {
            "header": {
                "initiator_spi": self.initiator_spi,
                "responder_spi": "SIMULATED_SERVER_SPI",
                "exchange_type": "CREATE_CHILD_SA"
            },
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
                {"type": "TS_I", "traffic_selectors": ["10.1.1.10/32"]},
                {"type": "TS_R", "traffic_selectors": ["10.1.1.0/24"]}
            ]
        }

    def start_simulation(self):
        print("\n[CLIENT] Starting IKEv2 Simulation...")

        # Simulate sending IKE_SA_INIT
        time.sleep(1)
        ike_init = self.build_ike_sa_init()
        print(f"[SEND] IKE_SA_INIT -> {json.dumps(ike_init, indent=2)}")

        # Simulate server response
        print("\n[SIMULATION] Receiving server IKE_SA_INIT response...")
        simulated_server_response = {
            "header": {
                "initiator_spi": ike_init["header"]["initiator_spi"],
                "responder_spi": os.urandom(8).hex(),
                "exchange_type": "IKE_SA_INIT"
            },
            "payloads": [
                ike_init["payloads"][0],  # SA
                {
                    "type": "KE",
                    "dh_group_id": 31,
                    "key_exchange_data": os.urandom(1024).hex()
                }
            ]
        }

        responder_spi = simulated_server_response["header"]["responder_spi"]
        print(f"[RECV] IKE_SA_INIT Response -> {json.dumps(simulated_server_response, indent=2)}")

        # Prepare IKE_AUTH
        time.sleep(1)
        ike_auth = self.build_ike_auth("server.pqc.vpn", "MOCK_SERVER_CERT")
        ike_auth["header"]["responder_spi"] = responder_spi
        print(f"[SEND] IKE_AUTH -> {json.dumps(ike_auth, indent=2)}")

        # Simulated server response with AUTH
        print("\n[SIMULATION] Receiving IKE_AUTH response from server...")
        simulated_auth_response = {
            "header": ike_auth["header"],
            "payloads": [
                {"type": "CERT", "certificate": "MOCK_SERVER_CERT"},
                {"type": "AUTH", "auth_method": "AUTH_METHOD_PKI", "signature": "mock_server_signature"}
            ]
        }

        print(f"[RECV] IKE_AUTH Response -> {json.dumps(simulated_auth_response, indent=2)}")

        # Simulate verifying server signature
        verified = verify_server_signature(
            simulated_auth_response["payloads"][0]["certificate"],
            "auth_data",  # Placeholder
            simulated_auth_response["payloads"][1]["signature"]
        )
        if not verified:
            print("[ERROR] Server authentication failed.")
            return
        print("[AUTH] Server authenticated successfully.")

        # Build CHILD_SA
        time.sleep(1)
        child_sa = self.build_child_sa()
        child_sa["header"]["responder_spi"] = responder_spi
        print(f"[SEND] CREATE_CHILD_SA -> {json.dumps(child_sa, indent=2)}")

        # Simulated CHILD_SA response
        print("\n[SIMULATION] Receiving CREATE_CHILD_SA response...")
        simulated_child_sa_response = child_sa  # Assume server mirrors request
        print(f"[RECV] CREATE_CHILD_SA Response -> {json.dumps(simulated_child_sa_response, indent=2)}")

        print("\n[INFO] IKEv2 Handshake simulation complete. Encrypted tunnel would now be established.")

# --- MAIN ---
if __name__ == "__main__":
    client = IKEClient()
    client.load_credentials("client.key.pem")
    client.start_simulation()
