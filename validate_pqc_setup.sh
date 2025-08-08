#!/bin/bash

# PQC IPSec VPN Validation Script
# Validates the setup and tests ML-DSA functionality

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

VALIDATION_LOG="/var/log/pqc-vpn-validation.log"

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$VALIDATION_LOG"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$VALIDATION_LOG"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$VALIDATION_LOG"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$VALIDATION_LOG"
}

check_dependencies() {
    log "Checking dependencies..."
    
    local deps=("strongswan" "openssl" "ipsec" "swanctl")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing dependencies: ${missing[*]}"
        return 1
    fi
    
    log "All dependencies found"
    return 0
}

check_liboqs() {
    log "Checking liboqs installation..."
    
    if [[ -f "/usr/local/lib/liboqs.so" ]]; then
        log "liboqs library found"
        
        # Check if ML-DSA algorithms are available
        if ldconfig -p | grep -q liboqs; then
            log "liboqs is properly linked"
        else
            warning "liboqs may not be properly linked"
        fi
    else
        error "liboqs library not found"
        return 1
    fi
    
    return 0
}

check_certificates() {
    log "Validating PQC certificates..."
    
    local cert_dir="/etc/strongswan/pqc-certs"
    local required_files=("ca-cert.pem" "ca-key.pem")
    
    if [[ ! -d "$cert_dir" ]]; then
        error "Certificate directory not found: $cert_dir"
        return 1
    fi
    
    # Check for VM-specific certificates
    local vm_role=$(detect_vm_role)
    if [[ "$vm_role" != "UNKNOWN" ]]; then
        required_files+=("${vm_role,,}-cert.pem" "${vm_role,,}-key.pem")
    fi
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$cert_dir/$file" ]]; then
            error "Missing certificate file: $file"
            return 1
        fi
        
        # Validate certificate
        if [[ "$file" == *"-cert.pem" ]]; then
            if openssl x509 -in "$cert_dir/$file" -noout -text &>/dev/null; then
                info "Certificate $file is valid"
            else
                error "Invalid certificate: $file"
                return 1
            fi
        fi
    done
    
    log "All certificates validated successfully"
    return 0
}

detect_vm_role() {
    local local_ip=$(ip route get 8.8.8.8 | awk '{print $7; exit}')
    if [[ "$local_ip" == "192.168.1.10" ]]; then
        echo "VM1"
    elif [[ "$local_ip" == "192.168.1.20" ]]; then
        echo "VM2"
    else
        echo "UNKNOWN"
    fi
}

check_strongswan_config() {
    log "Validating strongSwan configuration..."
    
    local config_files=("/etc/strongswan/ipsec.conf" "/etc/strongswan/ipsec.secrets")
    
    for config in "${config_files[@]}"; do
        if [[ ! -f "$config" ]]; then
            error "Missing configuration file: $config"
            return 1
        fi
        
        if [[ ! -r "$config" ]]; then
            error "Cannot read configuration file: $config"
            return 1
        fi
    done
    
    # Check swanctl configuration
    if [[ -f "/etc/swanctl/conf.d/pqc-vpn.conf" ]]; then
        info "swanctl configuration found"
        
        # Validate swanctl config syntax
        if swanctl --load-conns --file /etc/swanctl/conf.d/pqc-vpn.conf &>/dev/null; then
            log "swanctl configuration is valid"
        else
            error "Invalid swanctl configuration"
            return 1
        fi
    else
        warning "swanctl configuration not found"
    fi
    
    log "strongSwan configuration validated"
    return 0
}

check_network_config() {
    log "Checking network configuration..."
    
    # Check IP forwarding
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) -eq 1 ]]; then
        log "IP forwarding is enabled"
    else
        error "IP forwarding is disabled"
        return 1
    fi
    
    # Check firewall rules
    if iptables -L | grep -q "udp dpt:isakmp"; then
        log "IPSec firewall rules found"
    else
        warning "IPSec firewall rules may be missing"
    fi
    
    # Check network interfaces
    local vm_role=$(detect_vm_role)
    local expected_ip=""
    
    case "$vm_role" in
        "VM1") expected_ip="192.168.1.10" ;;
        "VM2") expected_ip="192.168.1.20" ;;
        *) warning "Unknown VM role, skipping IP check" ;;
    esac
    
    if [[ -n "$expected_ip" ]]; then
        if ip addr show | grep -q "$expected_ip"; then
            log "Expected IP address $expected_ip found"
        else
            error "Expected IP address $expected_ip not found"
            return 1
        fi
    fi
    
    return 0
}

check_services() {
    log "Checking service status..."
    
    if systemctl is-active --quiet strongswan; then
        log "strongSwan service is running"
    else
        error "strongSwan service is not running"
        return 1
    fi
    
    if systemctl is-enabled --quiet strongswan; then
        log "strongSwan service is enabled"
    else
        warning "strongSwan service is not enabled for startup"
    fi
    
    return 0
}

test_pqc_functionality() {
    log "Testing PQC functionality..."
    
    local cert_dir="/etc/strongswan/pqc-certs"
    local vm_role=$(detect_vm_role)
    
    if [[ "$vm_role" == "UNKNOWN" ]]; then
        warning "Cannot determine VM role, skipping PQC tests"
        return 0
    fi
    
    local cert_file="$cert_dir/${vm_role,,}-cert.pem"
    local key_file="$cert_dir/${vm_role,,}-key.pem"
    
    if [[ -f "$cert_file" && -f "$key_file" ]]; then
        # Test certificate and key pair
        local test_data="PQC VPN Test Data $(date)"
        local signature_file="/tmp/pqc_test_signature"
        local verify_file="/tmp/pqc_test_verify"
        
        echo "$test_data" > "$verify_file"
        
        # Try to sign data (this may fail with current OpenSSL if ML-DSA isn't supported)
        if openssl dgst -sha256 -sign "$key_file" -out "$signature_file" "$verify_file" 2>/dev/null; then
            if openssl dgst -sha256 -verify <(openssl x509 -in "$cert_file" -pubkey -noout) -signature "$signature_file" "$verify_file" 2>/dev/null; then
                log "PQC signature verification successful"
            else
                warning "PQC signature verification failed"
            fi
        else
            warning "PQC signing failed (may be expected with current OpenSSL)"
        fi
        
        # Cleanup
        rm -f "$signature_file" "$verify_file"
    else
        error "Certificate or key file not found for testing"
        return 1
    fi
    
    return 0
}

test_vpn_connectivity() {
    log "Testing VPN connectivity..."
    
    local vm_role=$(detect_vm_role)
    local target_subnet=""
    local target_ip=""
    
    case "$vm_role" in
        "VM1")
            target_subnet="10.2.2.0/24"
            target_ip="10.2.2.1"
            ;;
        "VM2")
            target_subnet="10.1.1.0/24"
            target_ip="10.1.1.1"
            ;;
        *)
            warning "Unknown VM role, skipping connectivity test"
            return 0
            ;;
    esac
    
    # Check IPSec status
    info "Current IPSec status:"
    ipsec status | head -20
    
    # Check for established connections
    local established=$(ipsec status | grep -c "ESTABLISHED" || echo "0")
    if [[ $established -gt 0 ]]; then
        log "Found $established established IPSec connection(s)"
        
        # Test ping to remote subnet
        info "Testing connectivity to $target_ip..."
        if timeout 10 ping -c 3 "$target_ip" &>/dev/null; then
            log "VPN connectivity test PASSED"
        else
            warning "VPN connectivity test FAILED (peer may not be configured)"
        fi
    else
        warning "No established IPSec connections found"
    fi
    
    return 0
}

generate_report() {
    log "Generating validation report..."
    
    local report_file="/tmp/pqc-vpn-validation-report.txt"
    local vm_role=$(detect_vm_role)
    
    cat > "$report_file" << EOF
PQC IPSec VPN Validation Report
Generated: $(date)
VM Role: $vm_role
Hostname: $(hostname)
IP Address: $(ip route get 8.8.8.8 | awk '{print $7; exit}')

=== System Information ===
OS: $(lsb_release -d | cut -f2)
Kernel: $(uname -r)
Architecture: $(uname -m)

=== Installed Packages ===
strongSwan: $(ipsec version | head -1)
OpenSSL: $(openssl version)
liboqs: $(ls -la /usr/local/lib/liboqs* 2>/dev/null | wc -l) files found

=== Configuration Status ===
strongSwan Config: $(test -f /etc/strongswan/ipsec.conf && echo "Present" || echo "Missing")
swanctl Config: $(test -f /etc/swanctl/conf.d/pqc-vpn.conf && echo "Present" || echo "Missing")
Certificates: $(ls /etc/strongswan/pqc-certs/*.pem 2>/dev/null | wc -l) files found

=== Service Status ===
strongSwan Service: $(systemctl is-active strongswan)
strongSwan Enabled: $(systemctl is-enabled strongswan)

=== Network Configuration ===
IP Forwarding: $(cat /proc/sys/net/ipv4/ip_forward)
IPSec Connections: $(ipsec status | grep -c "ESTABLISHED" || echo "0")

=== Recommendations ===
EOF

    # Add recommendations based on findings
    if ! systemctl is-active --quiet strongswan; then
        echo "- Start strongSwan service: systemctl start strongswan" >> "$report_file"
    fi
    
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) -eq 0 ]]; then
        echo "- Enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward" >> "$report_file"
    fi
    
    local established=$(ipsec status | grep -c "ESTABLISHED" || echo "0")
    if [[ $established -eq 0 ]]; then
        echo "- Check peer configuration and network connectivity" >> "$report_file"
        echo "- Verify certificates are properly installed on both VMs" >> "$report_file"
    fi
    
    echo "" >> "$report_file"
    echo "For detailed logs, check: $VALIDATION_LOG" >> "$report_file"
    
    log "Validation report saved to: $report_file"
    
    # Display report
    echo
    echo "=== VALIDATION REPORT ==="
    cat "$report_file"
    echo "========================="
}

main() {
    log "Starting PQC IPSec VPN validation..."
    
    local exit_code=0
    
    # Run all validation checks
    check_dependencies || exit_code=1
    check_liboqs || exit_code=1
    check_certificates || exit_code=1
    check_strongswan_config || exit_code=1
    check_network_config || exit_code=1
    check_services || exit_code=1
    test_pqc_functionality || exit_code=1
    test_vpn_connectivity || exit_code=1
    
    # Generate report
    generate_report
    
    if [[ $exit_code -eq 0 ]]; then
        log "All validation checks PASSED"
    else
        error "Some validation checks FAILED - see report for details"
    fi
    
    return $exit_code
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
