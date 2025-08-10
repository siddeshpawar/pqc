#!/bin/bash
# Ubuntu Installation Script for PQC VPN
# This script handles all dependencies and installation steps

set -e

echo "🔐 Post-Quantum Cryptography VPN - Ubuntu Installation"
echo "======================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root for system packages
check_sudo() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. This is not recommended for the entire script."
        print_warning "The script will use sudo when needed for system packages."
    fi
}

# Update package list
update_packages() {
    print_status "Updating package list..."
    sudo apt update || {
        print_error "Failed to update package list"
        exit 1
    }
    print_success "Package list updated"
}

# Install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    local packages=(
        "python3"
        "python3-pip"
        "python3-tk"
        "python3-dev"
        "build-essential"
        "cmake"
        "git"
        "libssl-dev"
        "ninja-build"
    )
    
    for package in "${packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            print_success "$package is already installed"
        else
            print_status "Installing $package..."
            sudo apt install -y "$package" || {
                print_error "Failed to install $package"
                exit 1
            }
        fi
    done
    
    print_success "System dependencies installed"
}

# Install liboqs from source (more reliable than package)
install_liboqs() {
    print_status "Installing liboqs library..."
    
    # Check if liboqs is already installed
    if pkg-config --exists liboqs; then
        print_success "liboqs is already installed"
        return 0
    fi
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    print_status "Cloning liboqs repository..."
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git || {
        print_error "Failed to clone liboqs repository"
        exit 1
    }
    
    cd liboqs
    
    print_status "Building liboqs..."
    mkdir build && cd build
    
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DOQS_BUILD_ONLY_LIB=ON \
          -DOQS_MINIMAL_BUILD="ML-DSA-44;ML-DSA-65;ML-DSA-87" \
          .. || {
        print_error "Failed to configure liboqs build"
        exit 1
    }
    
    ninja || {
        print_error "Failed to build liboqs"
        exit 1
    }
    
    print_status "Installing liboqs..."
    sudo ninja install || {
        print_error "Failed to install liboqs"
        exit 1
    }
    
    # Update library cache
    sudo ldconfig
    
    # Clean up
    cd /
    rm -rf "$TEMP_DIR"
    
    print_success "liboqs installed successfully"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Upgrade pip first
    python3 -m pip install --upgrade pip --break-system-packages || \
    python3 -m pip install --upgrade pip --user || {
        print_warning "Could not upgrade pip, continuing with existing version"
    }
    
    # Install liboqs-python
    print_status "Installing liboqs-python..."
    python3 -m pip install liboqs-python --break-system-packages || \
    python3 -m pip install liboqs-python --user || {
        print_error "Failed to install liboqs-python"
        print_error "You may need to install it manually after fixing liboqs installation"
    }
    
    print_success "Python dependencies installed"
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    # Test Python imports
    python3 -c "
import sys
try:
    import tkinter
    print('✓ tkinter available')
except ImportError as e:
    print('✗ tkinter not available:', e)
    sys.exit(1)

try:
    import oqs
    print('✓ liboqs-python available')
    
    # Test ML-DSA algorithms
    for alg in ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']:
        try:
            sig = oqs.Signature(alg)
            print(f'✓ {alg} supported')
        except Exception as e:
            print(f'✗ {alg} not supported:', e)
            
except ImportError as e:
    print('✗ liboqs-python not available:', e)
    print('You may need to install it manually')
" || {
        print_error "Installation verification failed"
        exit 1
    }
    
    print_success "Installation verified successfully"
}

# Install PQC VPN application
install_pqc_vpn() {
    print_status "Installing PQC VPN application..."
    
    # Create application directory
    sudo mkdir -p /usr/local/share/pqc-vpn
    sudo mkdir -p /usr/local/bin
    
    # Copy application files (assuming they're in current directory)
    if [ -f "pqc_vpn_gui.py" ]; then
        sudo cp pqc_vpn_gui.py /usr/local/share/pqc-vpn/
        print_success "GUI application installed"
    else
        print_warning "pqc_vpn_gui.py not found in current directory"
    fi
    
    if [ -f "pqc_vpn_certificate_working.py" ]; then
        sudo cp pqc_vpn_certificate_working.py /usr/local/share/pqc-vpn/
        print_success "Core VPN application installed"
    else
        print_warning "pqc_vpn_certificate_working.py not found in current directory"
    fi
    
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
    
    # Make scripts executable
    sudo chmod +x /usr/local/bin/pqc-vpn-gui
    sudo chmod +x /usr/local/bin/pqc-vpn
    
    # Create desktop entry
    sudo tee /usr/share/applications/pqc-vpn.desktop > /dev/null << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=PQC VPN
Comment=Post-Quantum Cryptography VPN with ML-DSA Certificates
Exec=pqc-vpn-gui
Icon=network-vpn
Terminal=false
StartupNotify=true
Categories=Network;Security;
Keywords=VPN;Quantum;Cryptography;Security;ML-DSA;
EOF
    
    print_success "PQC VPN application installed"
}

# Create certificate directory
setup_certificates() {
    print_status "Setting up certificate directory..."
    
    # Create user certificate directory
    CERT_DIR="$HOME/.config/pqc-vpn/certificates"
    mkdir -p "$CERT_DIR"/{client,server}
    
    print_success "Certificate directory created at $CERT_DIR"
    print_status "Please place your ML-DSA certificates in:"
    print_status "  Client certificates: $CERT_DIR/client/"
    print_status "  Server certificates: $CERT_DIR/server/"
}

# Main installation function
main() {
    print_status "Starting PQC VPN installation for Ubuntu..."
    
    check_sudo
    update_packages
    install_system_deps
    install_liboqs
    install_python_deps
    verify_installation
    install_pqc_vpn
    setup_certificates
    
    echo ""
    print_success "🎉 PQC VPN installation completed successfully!"
    echo ""
    print_status "You can now:"
    print_status "  • Run 'pqc-vpn-gui' to start the GUI application"
    print_status "  • Run 'pqc-vpn --help' for CLI usage"
    print_status "  • Find the app in Applications > Network > PQC VPN"
    echo ""
    print_status "Certificate directory: $HOME/.config/pqc-vpn/certificates"
    print_status "Place your ML-DSA certificates in client/ and server/ subdirectories"
    echo ""
}

# Run main function
main "$@"
