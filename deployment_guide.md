# PQC IPSec VPN Deployment Guide for EVE-NG

## Overview
This guide provides step-by-step instructions for deploying a Post-Quantum Cryptography (PQC) IPSec VPN using ML-DSA signatures between two Ubuntu VMs in EVE-NG.

## Prerequisites

### EVE-NG Environment
- EVE-NG Pro or Community Edition
- Ubuntu 20.04 LTS image imported
- Minimum 8GB RAM available for lab
- Internet connectivity for package downloads

### Network Topology
```
Client1 (10.1.1.100) ←→ [Switch-Net1] ←→ Ubuntu-VM1 (192.168.1.10) ←→ [WAN] ←→ Ubuntu-VM2 (192.168.1.20) ←→ [Switch-Net2] ←→ Client2 (10.2.2.100)
                                        ↓                                                    ↓
                                   LAN: 10.1.1.0/24                                   LAN: 10.2.2.0/24
```

## Deployment Steps

### Step 1: Import EVE-NG Topology

1. **Import the topology file:**
   ```bash
   # Copy eveng_topology_config.unl to your EVE-NG lab directory
   cp eveng_topology_config.unl /opt/unetlab/labs/admin/
   ```

2. **Start the lab in EVE-NG:**
   - Open EVE-NG web interface
   - Navigate to the imported lab
   - Start all nodes

### Step 2: Configure Network Interfaces

#### On Ubuntu-VM1 (192.168.1.10):
```bash
# Configure WAN interface
sudo ip addr add 192.168.1.10/24 dev eth0
sudo ip route add default via 192.168.1.1

# Configure LAN interface (if using dual-homed setup)
sudo ip addr add 10.1.1.1/24 dev eth1

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### On Ubuntu-VM2 (192.168.1.20):
```bash
# Configure WAN interface
sudo ip addr add 192.168.1.20/24 dev eth0
sudo ip route add default via 192.168.1.1

# Configure LAN interface
sudo ip addr add 10.2.2.1/24 dev eth1

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Step 3: Deploy PQC IPSec VPN

#### On both VMs:

1. **Copy the setup script:**
   ```bash
   # Transfer setup_pqc_ipsec_vpn.sh to both VMs
   scp setup_pqc_ipsec_vpn.sh user@vm-ip:/tmp/
   ```

2. **Make script executable:**
   ```bash
   chmod +x /tmp/setup_pqc_ipsec_vpn.sh
   ```

3. **Run the setup script:**
   ```bash
   sudo /tmp/setup_pqc_ipsec_vpn.sh
   ```

   The script will:
   - Auto-detect VM role (VM1 or VM2)
   - Install dependencies (strongSwan, liboqs, etc.)
   - Compile strongSwan with PQC support
   - Generate ML-DSA certificates
   - Configure IPSec tunnels
   - Start services

### Step 4: Validate Installation

#### Run validation script on both VMs:
```bash
# Copy and run validation script
chmod +x validate_pqc_setup.sh
sudo ./validate_pqc_setup.sh
```

#### Manual verification:
```bash
# Check strongSwan status
sudo ipsec status

# Check service status
sudo systemctl status strongswan

# View logs
sudo journalctl -u strongswan -f

# Test connectivity
ping 10.2.2.1  # From VM1 to VM2's LAN
ping 10.1.1.1  # From VM2 to VM1's LAN
```

### Step 5: Configure Client Networks

#### Client1 (10.1.1.100):
```bash
sudo ip addr add 10.1.1.100/24 dev eth0
sudo ip route add default via 10.1.1.1
```

#### Client2 (10.2.2.100):
```bash
sudo ip addr add 10.2.2.100/24 dev eth0
sudo ip route add default via 10.2.2.1
```

### Step 6: Test End-to-End Connectivity

#### From Client1:
```bash
# Test connectivity to Client2 through VPN tunnel
ping 10.2.2.100
traceroute 10.2.2.100

# Test with larger packets to verify ESP encapsulation
ping -s 1400 10.2.2.100
```

#### From Client2:
```bash
# Test connectivity to Client1 through VPN tunnel
ping 10.1.1.100
traceroute 10.1.1.100
```

## Configuration Details

### ML-DSA Implementation
- **Algorithm**: ML-DSA-65 (default, configurable)
- **Library**: liboqs (Open Quantum Safe)
- **Integration**: Custom strongSwan compilation with PQC support

### IPSec Configuration
- **Protocol**: IKEv2
- **Authentication**: Public key (ML-DSA certificates)
- **Encryption**: AES-256
- **Integrity**: SHA-256
- **PFS**: Modp2048 (with PQC key exchange when available)

### Certificate Hierarchy
```
CA Certificate (ML-DSA-65)
├── VM1 Certificate (ML-DSA-65)
└── VM2 Certificate (ML-DSA-65)
```

## Troubleshooting

### Common Issues

#### 1. strongSwan Service Fails to Start
```bash
# Check configuration syntax
sudo ipsec checkconfig

# Check logs
sudo journalctl -u strongswan --no-pager

# Restart service
sudo systemctl restart strongswan
```

#### 2. No IPSec Connections Established
```bash
# Check network connectivity
ping 192.168.1.20  # From VM1 to VM2

# Verify certificates
sudo openssl x509 -in /etc/strongswan/pqc-certs/vm1-cert.pem -text -noout

# Check firewall
sudo iptables -L | grep -E "(500|4500|esp)"
```

#### 3. Traffic Not Flowing Through Tunnel
```bash
# Check routing
ip route show

# Verify ESP traffic
sudo tcpdump -i eth0 esp

# Check strongSwan status
sudo swanctl --list-sas
```

### Debug Commands

#### Enable Debug Logging:
```bash
# Edit /etc/strongswan/strongswan.conf
charon {
    filelog {
        /var/log/charon.log {
            time_format = %b %e %T
            ike_name = yes
            append = no
            default = 2
            flush_line = yes
        }
    }
}
```

#### Monitor Traffic:
```bash
# Monitor IPSec traffic
sudo tcpdump -i any -n 'port 500 or port 4500 or proto esp'

# Monitor tunnel interface
sudo tcpdump -i any -n 'net 10.1.1.0/24 or net 10.2.2.0/24'
```

## Performance Testing

### Bandwidth Testing
```bash
# Install iperf3 on both client machines
sudo apt install iperf3

# On Client2 (server)
iperf3 -s

# On Client1 (client)
iperf3 -c 10.2.2.100 -t 60
```

### Latency Testing
```bash
# Continuous ping test
ping -i 0.1 10.2.2.100

# MTU discovery
ping -M do -s 1472 10.2.2.100
```

## Security Considerations

### Post-Quantum Readiness
- ML-DSA provides quantum-resistant digital signatures
- Current implementation uses hybrid approach (classical + PQC)
- Future-proof against quantum computing threats

### Certificate Management
- Certificates stored in `/etc/strongswan/pqc-certs/`
- Private keys protected with 600 permissions
- CA certificate shared between both VMs

### Network Security
- IPSec ESP provides encryption and authentication
- Perfect Forward Secrecy (PFS) enabled
- Strong cipher suites configured

## Maintenance

### Certificate Renewal
```bash
# Generate new certificates (run on both VMs)
cd /etc/strongswan/pqc-certs
sudo ./renew_certificates.sh
sudo systemctl restart strongswan
```

### Log Rotation
```bash
# Configure logrotate for strongSwan logs
sudo nano /etc/logrotate.d/strongswan
```

### Monitoring
```bash
# Check VPN status script
sudo /usr/local/bin/pqc-vpn-monitor.sh

# View monitoring logs
sudo journalctl -u pqc-vpn-monitor
```

## References

- [strongSwan Documentation](https://docs.strongswan.org/)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [ML-DSA Specification](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022)
- [EVE-NG Documentation](https://www.eve-ng.net/index.php/documentation/)

## Support

For issues and questions:
1. Check the validation report: `/tmp/pqc-vpn-validation-report.txt`
2. Review logs: `/var/log/pqc-ipsec-setup.log`
3. Monitor service: `sudo systemctl status strongswan`

---
*Generated for PQC IPSec VPN Laboratory - $(date)*
