#!/bin/bash
# Quick fix for Ubuntu PQC VPN dependencies

echo "🔧 Fixing Ubuntu dependencies for PQC VPN..."

# Install missing system packages
echo "Installing system dependencies..."
sudo apt update
sudo apt install -y python3-tk liboqs-dev python3-pip python3-dev build-essential

# Install Python packages
echo "Installing Python dependencies..."
pip3 install liboqs-python --break-system-packages || pip3 install liboqs-python --user

# Now try installing the .deb package again
echo "Dependencies installed. You can now install the .deb package:"
echo "sudo dpkg -i pqc-vpn_1.0.0_all.deb"

# Test the installation
echo "Testing installation..."
python3 -c "
try:
    import tkinter
    print('✅ tkinter available')
except ImportError:
    print('❌ tkinter not available')

try:
    import oqs
    print('✅ liboqs-python available')
    # Test ML-DSA
    sig = oqs.Signature('ML-DSA-44')
    print('✅ ML-DSA-44 working')
except ImportError as e:
    print('❌ liboqs-python not available:', e)
except Exception as e:
    print('⚠️ liboqs available but ML-DSA issue:', e)
"

echo "✅ Dependencies should now be ready!"
echo "Run: sudo dpkg -i pqc-vpn_1.0.0_all.deb"
