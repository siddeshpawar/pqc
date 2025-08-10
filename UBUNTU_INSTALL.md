# Ubuntu Installation Guide - PQC VPN

## Quick Fix for Dependency Issues

If you're getting dependency errors when installing the .deb package, follow these steps:

### Step 1: Install System Dependencies

```bash
# Update package list
sudo apt update

# Install required system packages
sudo apt install -y python3-tk liboqs-dev python3-pip python3-dev build-essential cmake git

# Install Python dependencies
pip3 install liboqs-python --break-system-packages
```

### Step 2: Install the .deb Package

```bash
# Now install the PQC VPN package
sudo dpkg -i pqc-vpn_1.0.0_all.deb

# Fix any remaining dependency issues
sudo apt-get install -f
```

### Step 3: Alternative - Manual Installation

If the .deb package still has issues, you can install manually:

```bash
# Create directories
sudo mkdir -p /usr/local/share/pqc-vpn
sudo mkdir -p /usr/local/bin

# Copy application files (from your current directory)
sudo cp pqc_vpn_gui.py /usr/local/share/pqc-vpn/
sudo cp pqc_vpn_certificate_working.py /usr/local/share/pqc-vpn/

# Create launcher scripts
sudo tee /usr/local/bin/pqc-vpn-gui > /dev/null << 'EOF'
#!/bin/bash
cd /usr/local/share/pqc-vpn
python3 pqc_vpn_gui.py "$@"
EOF

sudo tee /usr/local/bin/pqc-vpn > /dev/null << 'EOF'
#!/bin/bash
cd /usr/local/share/pqc-vpn
python3 pqc_vpn_certificate_working.py "$@"
EOF

# Make executable
sudo chmod +x /usr/local/bin/pqc-vpn-gui
sudo chmod +x /usr/local/bin/pqc-vpn

# Create desktop entry
sudo tee /usr/share/applications/pqc-vpn.desktop > /dev/null << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=PQC VPN
Comment=Post-Quantum Cryptography VPN
Exec=pqc-vpn-gui
Icon=network-vpn
Terminal=false
Categories=Network;Security;
EOF
```

### Step 4: Test Installation

```bash
# Test dependencies
python3 -c "
import tkinter
import oqs
print('✅ All dependencies working!')

# Test ML-DSA
sig = oqs.Signature('ML-DSA-44')
print('✅ ML-DSA-44 available')
"

# Launch GUI
pqc-vpn-gui
```

### Step 5: Create Certificate Directory

```bash
# Create certificate directory
mkdir -p ~/.config/pqc-vpn/certificates/{client,server}

echo "Certificate directory created at: ~/.config/pqc-vpn/certificates"
echo "Place your ML-DSA certificates in client/ and server/ subdirectories"
```

## Usage

### GUI Mode
```bash
pqc-vpn-gui
```

### CLI Mode
```bash
# Show help
pqc-vpn

# Run VPN
pqc-vpn 192.168.1.10 192.168.1.20 ~/.config/pqc-vpn/certificates initiator

# With debug5 mode
pqc-vpn 192.168.1.10 192.168.1.20 ~/.config/pqc-vpn/certificates initiator debug5
```

## Troubleshooting

### If liboqs-dev is not available in your Ubuntu version:

```bash
# Install from source
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

### If you get permission errors:

```bash
# Add your user to necessary groups
sudo usermod -a -G netdev $USER

# Logout and login again, or run:
newgrp netdev
```

### Test ML-DSA algorithms:

```bash
python3 -c "
import oqs
for alg in ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']:
    try:
        sig = oqs.Signature(alg)
        print(f'✅ {alg} working')
    except:
        print(f'❌ {alg} not available')
"
```
