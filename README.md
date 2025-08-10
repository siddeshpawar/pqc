# Post-Quantum Cryptography VPN

A secure VPN implementation using post-quantum cryptographic algorithms including ML-DSA (Module-Lattice-Based Digital Signature Algorithm) for quantum-resistant security.

## 🔐 Features

- **Post-Quantum Security**: ML-DSA-44, ML-DSA-65, and ML-DSA-87 support
- **Certificate Chain Validation**: Full X.509 certificate chain with ML-DSA signatures
- **Simple GUI Interface**: Easy-to-use graphical interface for configuration
- **CLI Support**: Command-line interface for advanced users and automation
- **Debug5 Mode**: Detailed mathematical analysis and cryptographic insights
- **Cross-Platform**: Windows and Ubuntu/Linux support

## 📦 Installation

### Windows (.exe installer)

1. Download `PQC-VPN-Installer.exe`
2. Run the installer as administrator
3. Follow the installation wizard
4. Launch from Start Menu or Desktop shortcut

### Ubuntu/Debian (.deb package)

```bash
# Install the package
sudo dpkg -i pqc-vpn_1.0.0_all.deb

# Fix any dependency issues
sudo apt-get install -f

# Launch GUI
pqc-vpn-gui

# Or use CLI
pqc-vpn --help
```

## 🚀 Quick Start

### GUI Mode

1. Launch the PQC VPN application
2. Configure your network settings:
   - **Local IP**: Your machine's IP address
   - **Remote IP**: The peer's IP address
   - **Certificate Directory**: Path to your ML-DSA certificates
   - **Role**: Choose Initiator or Responder
3. Click "Validate Certificates" to check your certificate setup
4. Click "Start VPN" to establish the connection
5. Monitor the status and logs in the application

### CLI Mode

```bash
# Initiator (connects to responder)
pqc-vpn 192.168.1.10 192.168.1.20 /path/to/certs initiator

# Responder (waits for connections)
pqc-vpn 192.168.1.20 192.168.1.10 /path/to/certs responder

# With debug5 mode for detailed analysis
pqc-vpn 192.168.1.20 192.168.1.10 /path/to/certs responder debug5
```

## 📁 Certificate Setup

The application requires ML-DSA certificates organized in the following structure:

```
certificate_directory/
├── client/
│   ├── end_entity.crt    # ML-DSA end-entity certificate
│   ├── intermediate.crt  # ML-DSA intermediate CA (optional)
│   └── root_ca.crt      # ML-DSA root CA
└── server/
    ├── end_entity.crt    # ML-DSA end-entity certificate
    ├── intermediate.crt  # ML-DSA intermediate CA (optional)
    └── root_ca.crt      # ML-DSA root CA
```

### Supported ML-DSA Algorithms

| Algorithm | Security Level | Public Key Size | Signature Size | Use Case |
|-----------|----------------|-----------------|----------------|----------|
| ML-DSA-44 | Level 2        | 1,312 bytes     | 2,420 bytes    | Standard security |
| ML-DSA-65 | Level 3        | 1,952 bytes     | 3,309 bytes    | High security |
| ML-DSA-87 | Level 5        | 2,592 bytes     | 4,627 bytes    | Maximum security |

## 🔬 Debug5 Mode

Enable Debug5 mode for detailed cryptographic analysis:

- **Mathematical Parameters**: Detailed ML-DSA algorithm specifications
- **Certificate Visualization**: PEM structure and content analysis
- **Network Packet Analysis**: Deep packet inspection and format detection
- **Progress Tracking**: Visual progress bars for all operations
- **Cryptographic Insights**: Step-by-step signature and verification process

## 🛠️ Building from Source

### Prerequisites

```bash
# Python dependencies
pip install tkinter liboqs-python

# System dependencies (Ubuntu)
sudo apt install liboqs-dev python3-tk dpkg-dev

# System dependencies (Windows)
# Install Python 3.8+ with tkinter
# Install Visual Studio Build Tools
```

### Build Windows Installer

```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
python build_windows.py

# Create installer (requires NSIS)
# Right-click pqc_vpn_installer.nsi and select "Compile NSIS Script"
```

### Build Ubuntu Package

```bash
# Build .deb package
python build_ubuntu.py

# Install locally
sudo dpkg -i pqc-vpn_1.0.0_all.deb
```

### Build All Packages

```bash
# Test GUI
python build_all.py --test-gui

# Build Windows package
python build_all.py --windows

# Build Ubuntu package  
python build_all.py --ubuntu

# Build all packages
python build_all.py --all
```

## 🔧 Configuration

### Network Configuration

The VPN creates tunnel interfaces with the following default settings:

- **Initiator**: `pqc-chain0` with IP `10.100.0.1/30`
- **Responder**: `pqc-chain1` with IP `10.100.0.2/30`

### Firewall Configuration

Ensure the following ports are open:

- **UDP 5001**: VPN communication port
- **ICMP**: For connectivity testing

## 📊 Status Indicators

The GUI provides real-time status information:

- **IKE Status**: Internet Key Exchange establishment
- **Tunnel Status**: VPN tunnel active/inactive
- **Certificate Status**: Certificate validation results
- **Connection Logs**: Detailed operation logs

## 🔍 Troubleshooting

### Common Issues

1. **Certificate Validation Failed**
   - Check certificate file paths
   - Verify ML-DSA algorithm compatibility
   - Ensure proper certificate chain order

2. **Connection Timeout**
   - Verify IP addresses and network connectivity
   - Check firewall settings
   - Ensure both peers are configured correctly

3. **liboqs Not Found**
   ```bash
   # Ubuntu
   sudo apt install liboqs-dev
   pip install liboqs-python
   
   # Windows
   pip install liboqs-python
   ```

### Debug Mode

Use Debug5 mode for detailed troubleshooting:

```bash
pqc-vpn 192.168.1.20 192.168.1.10 certs responder debug5
```

This provides:
- Mathematical parameter analysis
- Certificate structure visualization
- Network packet deep inspection
- Cryptographic operation insights

## 🔒 Security Considerations

- **Quantum Resistance**: ML-DSA provides security against quantum computer attacks
- **Certificate Management**: Use proper certificate rotation and management practices
- **Network Security**: Deploy in secure network environments
- **Key Storage**: Protect private keys with appropriate access controls

## 📚 Technical Details

### ML-DSA Implementation

The application uses the liboqs library for ML-DSA operations:

- **Signature Generation**: Real post-quantum signature creation
- **Signature Verification**: Cryptographic signature validation
- **Key Management**: Automatic algorithm detection and key handling
- **Certificate Integration**: X.509 certificate chain with ML-DSA signatures

### Network Protocol

- **Transport**: UDP with JSON message format
- **Handshake**: ML-DSA certificate chain exchange
- **Authentication**: Mutual authentication using ML-DSA signatures
- **Tunnel Creation**: TUN interface with IP routing

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:

- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Check the project wiki for detailed guides
- **Community**: Join our discussions for help and tips

## 🔗 Links

- **liboqs**: https://github.com/open-quantum-safe/liboqs
- **ML-DSA Specification**: NIST FIPS 204
- **Post-Quantum Cryptography**: https://csrc.nist.gov/projects/post-quantum-cryptography

---

**⚠️ Note**: This is experimental software. Use in production environments only after thorough testing and security review.
