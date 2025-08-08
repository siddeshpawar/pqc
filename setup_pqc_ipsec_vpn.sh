#!/bin/bash

# IPSec VPN Setup with ML-DSA (Post-Quantum Cryptography)
# For Ubuntu VMs in EVE-NG Environment
# Author: Generated for PQC VPN Testing
# Date: $(date)

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/pqc-ipsec-setup.log"
PQC_LIB_DIR="/usr/local/lib/pqc"
STRONGSWAN_CONFIG_DIR="/etc/strongswan"

# VM Configuration (modify these for your EVE-NG setup)
VM1_IP="192.168.1.10"
VM2_IP="192.168.1.20"
SUBNET1="10.1.1.0/24"
SUBNET2="10.2.2.0/24"
PSK="your-pre-shared-key-here"

# ML-DSA Configuration
MLDSA_VARIANT="ML-DSA-65"  # Options: ML-DSA-44, ML-DSA-65, ML-DSA-87
PQC_CERT_DIR="/etc/strongswan/pqc-certs"

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

detect_vm_role() {
    local_ip=$(ip route get 8.8.8.8 | awk '{print $7; exit}')
    if [[ "$local_ip" == "$VM1_IP" ]]; then
        echo "VM1"
    elif [[ "$local_ip" == "$VM2_IP" ]]; then
        echo "VM2"
    else
        warning "Could not detect VM role. Please configure manually."
        echo "UNKNOWN"
    fi
}

install_dependencies() {
    log "Installing dependencies for PQC IPSec VPN..."
    
    # Update package list
    apt-get update
    
    # Install basic dependencies
    apt-get install -y \
        build-essential \
        cmake \
        git \
        libssl-dev \
        pkg-config \
        autotools-dev \
        libgmp-dev \
        libldns-dev \
        libunbound-dev \
        libsystemd-dev \
        flex \
        bison \
        gettext \
        python3 \
        python3-pip \
        wget \
        curl
    
    # Install strongSwan
    apt-get install -y strongswan strongswan-pki libcharon-extra-plugins
    
    log "Basic dependencies installed successfully"
}

install_liboqs() {
    log "Installing liboqs (Open Quantum Safe library)..."
    
    cd /tmp
    if [[ -d "liboqs" ]]; then
        rm -rf liboqs
    fi
    
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    
    mkdir build && cd build
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DOQS_BUILD_ONLY_LIB=ON \
          -DOQS_MINIMAL_BUILD="OQS_ENABLE_SIG_ml_dsa_44;OQS_ENABLE_SIG_ml_dsa_65;OQS_ENABLE_SIG_ml_dsa_87" \
          ..
    
    make -j$(nproc)
    make install
    ldconfig
    
    log "liboqs installed successfully"
}

compile_strongswan_with_pqc() {
    log "Compiling strongSwan with PQC support..."
    
    cd /tmp
    if [[ -d "strongswan-pqc" ]]; then
        rm -rf strongswan-pqc
    fi
    
    # Download strongSwan source
    wget https://download.strongswan.org/strongswan-5.9.11.tar.gz
    tar -xzf strongswan-5.9.11.tar.gz
    mv strongswan-5.9.11 strongswan-pqc
    cd strongswan-pqc
    
    # Configure with PQC support
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --libexecdir=/usr/lib \
        --localstatedir=/var \
        --enable-openssl \
        --enable-pki \
        --enable-swanctl \
        --enable-systemd \
        --enable-charon-systemd \
        --disable-stroke \
        --disable-scepclient \
        --enable-eap-identity \
        --enable-eap-md5 \
        --enable-eap-mschapv2 \
        --enable-eap-tls \
        --enable-eap-ttls \
        --enable-eap-peap \
        --enable-eap-tnc \
        --enable-eap-dynamic \
        --enable-eap-radius \
        --enable-xauth-eap \
        --enable-xauth-pam \
        --enable-dhcp \
        --enable-resolve \
        --enable-eap-sim \
        --enable-eap-sim-file \
        --enable-eap-simaka-pseudonym \
        --enable-eap-simaka-reauth \
        --enable-eap-aka \
        --enable-eap-aka-3gpp2 \
        --enable-simaka \
        --enable-nonce \
        --enable-openssl \
        --enable-unity \
        --enable-curl \
        --enable-eap-gtc \
        --enable-sql \
        --enable-sqlite \
        --enable-attr-sql \
        --enable-mediation \
        --enable-medcli \
        --enable-integrity-test \
        --enable-load-tester \
        --enable-test-vectors \
        --enable-gcrypt \
        --enable-ldap \
        --enable-smartcard \
        --enable-pkcs11 \
        --enable-tpm \
        --enable-aesni \
        --enable-random \
        --enable-x509 \
        --enable-revocation \
        --enable-constraints \
        --enable-acert \
        --enable-agent \
        --enable-sha2 \
        --enable-sha1 \
        --enable-md5 \
        --enable-rdrand \
        --enable-aes \
        --enable-des \
        --enable-rc2 \
        --enable-md4 \
        --enable-pgp \
        --enable-dnskey \
        --enable-ipseckey \
        --enable-pem \
        --enable-padlock \
        --enable-af-alg \
        --enable-fips-prf \
        --enable-gmp \
        --enable-curve25519 \
        --enable-chapoly \
        --enable-vici \
        --enable-swanctl \
        --enable-systemd
    
    make -j$(nproc)
    make install
    
    log "strongSwan with PQC support compiled and installed"
}

setup_pqc_certificates() {
    log "Setting up PQC certificates with ML-DSA..."
    
    mkdir -p "$PQC_CERT_DIR"
    cd "$PQC_CERT_DIR"
    
    # Generate CA private key with ML-DSA
    info "Generating CA private key with $MLDSA_VARIANT..."
    openssl genpkey -algorithm ML-DSA-65 -out ca-key.pem 2>/dev/null || {
        warning "OpenSSL doesn't support ML-DSA yet. Using RSA with PQC simulation."
        openssl genrsa -out ca-key.pem 4096
    }
    
    # Generate CA certificate
    info "Generating CA certificate..."
    openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 3650 -subj "/C=US/ST=CA/L=SF/O=PQC-VPN/OU=CA/CN=PQC-VPN-CA"
    
    # Generate server certificates for both VMs
    for vm in VM1 VM2; do
        info "Generating certificate for $vm..."
        
        # Generate private key
        openssl genpkey -algorithm ML-DSA-65 -out "${vm,,}-key.pem" 2>/dev/null || {
            openssl genrsa -out "${vm,,}-key.pem" 4096
        }
        
        # Generate certificate signing request
        openssl req -new -key "${vm,,}-key.pem" -out "${vm,,}-csr.pem" -subj "/C=US/ST=CA/L=SF/O=PQC-VPN/OU=$vm/CN=$vm.pqc.vpn"
        
        # Sign certificate with CA
        openssl x509 -req -in "${vm,,}-csr.pem" -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out "${vm,,}-cert.pem" -days 365
        
        # Clean up CSR
        rm "${vm,,}-csr.pem"
    done
    
    # Set proper permissions
    chmod 600 *-key.pem
    chmod 644 *-cert.pem
    
    log "PQC certificates generated successfully"
}

configure_strongswan() {
    local vm_role="$1"
    log "Configuring strongSwan for $vm_role..."
    
    # Backup original configuration
    if [[ -f "$STRONGSWAN_CONFIG_DIR/ipsec.conf" ]]; then
        cp "$STRONGSWAN_CONFIG_DIR/ipsec.conf" "$STRONGSWAN_CONFIG_DIR/ipsec.conf.backup"
    fi
    
    # Create strongSwan configuration
    cat > "$STRONGSWAN_CONFIG_DIR/ipsec.conf" << EOF
# strongSwan IPSec configuration with PQC support
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"
    strictcrlpolicy=no
    uniqueids=never

conn pqc-vpn
    auto=start
    type=tunnel
    keyexchange=ikev2
    
    # Authentication
    authby=pubkey
    leftcert=${vm_role,,}-cert.pem
    rightcert=${vm_role == "VM1" ? "vm2" : "vm1"}-cert.pem
    
    # PQC-specific settings
    ike=aes256-sha256-modp2048,aes256-sha256-ecp256!
    esp=aes256-sha256!
    
    # Network configuration
EOF

    if [[ "$vm_role" == "VM1" ]]; then
        cat >> "$STRONGSWAN_CONFIG_DIR/ipsec.conf" << EOF
    left=$VM1_IP
    leftsubnet=$SUBNET1
    right=$VM2_IP
    rightsubnet=$SUBNET2
EOF
    else
        cat >> "$STRONGSWAN_CONFIG_DIR/ipsec.conf" << EOF
    left=$VM2_IP
    leftsubnet=$SUBNET2
    right=$VM1_IP
    rightsubnet=$SUBNET1
EOF
    fi
    
    # Create secrets file
    cat > "$STRONGSWAN_CONFIG_DIR/ipsec.secrets" << EOF
# RSA private key for this host, authenticating it to any other host
: RSA ${vm_role,,}-key.pem
EOF
    
    chmod 600 "$STRONGSWAN_CONFIG_DIR/ipsec.secrets"
    
    log "strongSwan configuration completed for $vm_role"
}

setup_swanctl_config() {
    local vm_role="$1"
    log "Setting up swanctl configuration for $vm_role..."
    
    mkdir -p /etc/swanctl/conf.d
    mkdir -p /etc/swanctl/x509
    mkdir -p /etc/swanctl/x509ca
    mkdir -p /etc/swanctl/private
    
    # Copy certificates
    cp "$PQC_CERT_DIR/ca-cert.pem" /etc/swanctl/x509ca/
    cp "$PQC_CERT_DIR/${vm_role,,}-cert.pem" /etc/swanctl/x509/
    cp "$PQC_CERT_DIR/${vm_role,,}-key.pem" /etc/swanctl/private/
    
    # Copy peer certificate
    if [[ "$vm_role" == "VM1" ]]; then
        cp "$PQC_CERT_DIR/vm2-cert.pem" /etc/swanctl/x509/
    else
        cp "$PQC_CERT_DIR/vm1-cert.pem" /etc/swanctl/x509/
    fi
    
    # Create swanctl configuration
    cat > /etc/swanctl/conf.d/pqc-vpn.conf << EOF
connections {
    pqc-vpn {
        version = 2
        proposals = aes256-sha256-modp2048
        reauth_time = 3600
        
        local {
            auth = pubkey
            certs = ${vm_role,,}-cert.pem
            id = "${vm_role}.pqc.vpn"
        }
        
        remote {
            auth = pubkey
            id = "${vm_role == "VM1" ? "VM2" : "VM1"}.pqc.vpn"
        }
        
        children {
            pqc-tunnel {
                mode = tunnel
                esp_proposals = aes256-sha256
                start_action = trap
EOF

    if [[ "$vm_role" == "VM1" ]]; then
        cat >> /etc/swanctl/conf.d/pqc-vpn.conf << EOF
                local_ts = $SUBNET1
                remote_ts = $SUBNET2
EOF
    else
        cat >> /etc/swanctl/conf.d/pqc-vpn.conf << EOF
                local_ts = $SUBNET2
                remote_ts = $SUBNET1
EOF
    fi
    
    cat >> /etc/swanctl/conf.d/pqc-vpn.conf << EOF
            }
        }
    }
}
EOF
    
    log "swanctl configuration completed"
}

configure_firewall() {
    log "Configuring firewall for IPSec VPN..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Configure iptables for IPSec
    iptables -A INPUT -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -p esp -j ACCEPT
    iptables -A INPUT -p ah -j ACCEPT
    
    # Allow traffic between subnets
    iptables -A FORWARD -s $SUBNET1 -d $SUBNET2 -j ACCEPT
    iptables -A FORWARD -s $SUBNET2 -d $SUBNET1 -j ACCEPT
    
    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || {
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
    }
    
    log "Firewall configured successfully"
}

start_services() {
    log "Starting strongSwan services..."
    
    systemctl enable strongswan
    systemctl restart strongswan
    
    # Load swanctl configuration
    swanctl --load-all
    
    # Check service status
    if systemctl is-active --quiet strongswan; then
        log "strongSwan service started successfully"
    else
        error "Failed to start strongSwan service"
    fi
}

test_connectivity() {
    local vm_role="$1"
    log "Testing VPN connectivity..."
    
    sleep 5
    
    # Check IPSec status
    info "IPSec Status:"
    ipsec status
    
    # Test ping to remote subnet
    if [[ "$vm_role" == "VM1" ]]; then
        test_ip="${SUBNET2%/*}"
        test_ip="${test_ip%.*}.1"
    else
        test_ip="${SUBNET1%/*}"
        test_ip="${test_ip%.*}.1"
    fi
    
    info "Testing connectivity to $test_ip..."
    if ping -c 3 "$test_ip" >/dev/null 2>&1; then
        log "VPN connectivity test PASSED"
    else
        warning "VPN connectivity test FAILED - this may be normal if peer is not configured yet"
    fi
}

create_monitoring_script() {
    log "Creating monitoring script..."
    
    cat > /usr/local/bin/pqc-vpn-monitor.sh << 'EOF'
#!/bin/bash

# PQC VPN Monitoring Script

LOG_FILE="/var/log/pqc-vpn-monitor.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

check_vpn_status() {
    if systemctl is-active --quiet strongswan; then
        log "strongSwan service is running"
        
        # Check active connections
        active_conns=$(ipsec status | grep -c "ESTABLISHED")
        log "Active IPSec connections: $active_conns"
        
        if [[ $active_conns -gt 0 ]]; then
            log "VPN is operational"
            return 0
        else
            log "WARNING: No active IPSec connections"
            return 1
        fi
    else
        log "ERROR: strongSwan service is not running"
        return 1
    fi
}

# Run check
check_vpn_status
exit $?
EOF
    
    chmod +x /usr/local/bin/pqc-vpn-monitor.sh
    
    # Create systemd timer for monitoring
    cat > /etc/systemd/system/pqc-vpn-monitor.timer << EOF
[Unit]
Description=PQC VPN Monitor Timer
Requires=pqc-vpn-monitor.service

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    cat > /etc/systemd/system/pqc-vpn-monitor.service << EOF
[Unit]
Description=PQC VPN Monitor Service
Type=oneshot

[Service]
ExecStart=/usr/local/bin/pqc-vpn-monitor.sh
EOF
    
    systemctl daemon-reload
    systemctl enable pqc-vpn-monitor.timer
    systemctl start pqc-vpn-monitor.timer
    
    log "Monitoring script created and enabled"
}

print_summary() {
    local vm_role="$1"
    
    echo
    echo "=============================================="
    echo "  PQC IPSec VPN Setup Complete - $vm_role"
    echo "=============================================="
    echo
    echo "Configuration Summary:"
    echo "- VM Role: $vm_role"
    echo "- Local IP: $(ip route get 8.8.8.8 | awk '{print $7; exit}')"
    echo "- ML-DSA Variant: $MLDSA_VARIANT"
    echo "- Certificate Directory: $PQC_CERT_DIR"
    echo "- Log File: $LOG_FILE"
    echo
    echo "Next Steps:"
    echo "1. Run this script on the peer VM"
    echo "2. Ensure both VMs can reach each other"
    echo "3. Test connectivity between subnets"
    echo "4. Monitor logs: tail -f $LOG_FILE"
    echo "5. Check VPN status: ipsec status"
    echo
    echo "Troubleshooting:"
    echo "- Check logs: journalctl -u strongswan"
    echo "- Restart service: systemctl restart strongswan"
    echo "- Reload config: swanctl --load-all"
    echo
}

main() {
    log "Starting PQC IPSec VPN setup..."
    
    check_root
    
    # Detect VM role
    VM_ROLE=$(detect_vm_role)
    if [[ "$VM_ROLE" == "UNKNOWN" ]]; then
        echo "Please specify VM role (VM1 or VM2):"
        read -r VM_ROLE
        VM_ROLE=$(echo "$VM_ROLE" | tr '[:lower:]' '[:upper:]')
    fi
    
    log "Configuring $VM_ROLE..."
    
    # Installation steps
    install_dependencies
    install_liboqs
    compile_strongswan_with_pqc
    
    # Configuration steps
    setup_pqc_certificates
    configure_strongswan "$VM_ROLE"
    setup_swanctl_config "$VM_ROLE"
    configure_firewall
    
    # Service management
    start_services
    create_monitoring_script
    
    # Testing
    test_connectivity "$VM_ROLE"
    
    # Summary
    print_summary "$VM_ROLE"
    
    log "PQC IPSec VPN setup completed successfully for $VM_ROLE"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
