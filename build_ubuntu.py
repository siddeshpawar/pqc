#!/usr/bin/env python3
"""
Ubuntu .deb Package Build Script for PQC VPN GUI Application
Creates a .deb package for easy installation on Ubuntu/Debian systems
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import tempfile

def create_debian_structure(build_dir):
    """Create the Debian package directory structure"""
    package_name = "pqc-vpn"
    version = "1.0.0"
    
    # Create directory structure
    debian_dir = os.path.join(build_dir, f"{package_name}_{version}")
    
    dirs = [
        "DEBIAN",
        "usr/bin",
        "usr/share/applications",
        "usr/share/pixmaps",
        "usr/share/doc/pqc-vpn",
        "usr/lib/pqc-vpn"
    ]
    
    for dir_path in dirs:
        os.makedirs(os.path.join(debian_dir, dir_path), exist_ok=True)
    
    return debian_dir, package_name, version

def create_control_file(debian_dir, package_name, version):
    """Create the DEBIAN/control file"""
    control_content = f"""Package: {package_name}
Version: {version}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.8), python3-tk, python3-pip, liboqs-dev
Maintainer: PQC VPN Team <support@pqcvpn.org>
Description: Post-Quantum Cryptography VPN with ML-DSA Certificates
 A secure VPN implementation using post-quantum cryptographic algorithms
 including ML-DSA (Module-Lattice-Based Digital Signature Algorithm) for
 quantum-resistant security.
 .
 Features:
  * ML-DSA-44, ML-DSA-65, and ML-DSA-87 support
  * Certificate chain validation
  * Simple GUI interface for configuration
  * Debug mode with detailed cryptographic analysis
  * Cross-platform compatibility
Homepage: https://github.com/your-repo/pqc-vpn
"""
    
    control_file = os.path.join(debian_dir, "DEBIAN", "control")
    with open(control_file, 'w') as f:
        f.write(control_content)
    
    print(f"Created control file: {control_file}")

def create_postinst_script(debian_dir):
    """Create post-installation script"""
    postinst_content = """#!/bin/bash
set -e

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install liboqs-python --break-system-packages 2>/dev/null || pip3 install liboqs-python

# Create certificate directory
mkdir -p /etc/pqc-vpn/certificates
chmod 755 /etc/pqc-vpn
chmod 700 /etc/pqc-vpn/certificates

# Set permissions
chmod +x /usr/bin/pqc-vpn
chmod +x /usr/bin/pqc-vpn-gui

echo "PQC VPN installation completed successfully!"
echo "You can start the application from the Applications menu or run 'pqc-vpn-gui' in terminal."

exit 0
"""
    
    postinst_file = os.path.join(debian_dir, "DEBIAN", "postinst")
    with open(postinst_file, 'w') as f:
        f.write(postinst_content)
    
    os.chmod(postinst_file, 0o755)
    print(f"Created postinst script: {postinst_file}")

def create_prerm_script(debian_dir):
    """Create pre-removal script"""
    prerm_content = """#!/bin/bash
set -e

# Stop any running VPN processes
pkill -f pqc_vpn_certificate_working.py 2>/dev/null || true

echo "PQC VPN processes stopped."

exit 0
"""
    
    prerm_file = os.path.join(debian_dir, "DEBIAN", "prerm")
    with open(prerm_file, 'w') as f:
        f.write(prerm_content)
    
    os.chmod(prerm_file, 0o755)
    print(f"Created prerm script: {prerm_file}")

def create_desktop_file(debian_dir):
    """Create .desktop file for GUI application"""
    desktop_content = """[Desktop Entry]
Version=1.0
Type=Application
Name=PQC VPN
Comment=Post-Quantum Cryptography VPN with ML-DSA Certificates
Exec=pqc-vpn-gui
Icon=pqc-vpn
Terminal=false
StartupNotify=true
Categories=Network;Security;
Keywords=VPN;Quantum;Cryptography;Security;ML-DSA;
"""
    
    desktop_file = os.path.join(debian_dir, "usr", "share", "applications", "pqc-vpn.desktop")
    with open(desktop_file, 'w') as f:
        f.write(desktop_content)
    
    print(f"Created desktop file: {desktop_file}")

def create_launcher_scripts(debian_dir):
    """Create launcher scripts"""
    # GUI launcher
    gui_launcher = """#!/bin/bash
# PQC VPN GUI Launcher
cd /usr/lib/pqc-vpn
python3 pqc_vpn_gui.py "$@"
"""
    
    gui_script = os.path.join(debian_dir, "usr", "bin", "pqc-vpn-gui")
    with open(gui_script, 'w') as f:
        f.write(gui_launcher)
    os.chmod(gui_script, 0o755)
    
    # CLI launcher
    cli_launcher = """#!/bin/bash
# PQC VPN CLI Launcher
cd /usr/lib/pqc-vpn
python3 pqc_vpn_certificate_working.py "$@"
"""
    
    cli_script = os.path.join(debian_dir, "usr", "bin", "pqc-vpn")
    with open(cli_script, 'w') as f:
        f.write(cli_launcher)
    os.chmod(cli_script, 0o755)
    
    print("Created launcher scripts")

def copy_application_files(debian_dir):
    """Copy application files to package"""
    lib_dir = os.path.join(debian_dir, "usr", "lib", "pqc-vpn")
    
    # Copy main application files
    files_to_copy = [
        "pqc_vpn_gui.py",
        "pqc_vpn_certificate_working.py"
    ]
    
    for file_name in files_to_copy:
        if os.path.exists(file_name):
            shutil.copy2(file_name, lib_dir)
            print(f"Copied {file_name}")
        else:
            print(f"Warning: {file_name} not found")
    
    # Copy documentation
    doc_dir = os.path.join(debian_dir, "usr", "share", "doc", "pqc-vpn")
    
    # Create README
    readme_content = """# Post-Quantum Cryptography VPN

A secure VPN implementation using post-quantum cryptographic algorithms.

## Features

- ML-DSA-44, ML-DSA-65, and ML-DSA-87 support
- Certificate chain validation
- Simple GUI interface for configuration
- Debug mode with detailed cryptographic analysis

## Usage

### GUI Mode
Run `pqc-vpn-gui` from the applications menu or terminal.

### CLI Mode
```bash
pqc-vpn <local_ip> <remote_ip> <cert_dir> <initiator|responder> [debug5]
```

## Configuration

1. Prepare ML-DSA certificates in the certificate directory
2. Configure IP addresses for local and remote endpoints
3. Select role (initiator or responder)
4. Start the VPN connection

## Requirements

- Python 3.8+
- liboqs library
- ML-DSA certificates

## Support

For support and documentation, visit: https://github.com/your-repo/pqc-vpn
"""
    
    with open(os.path.join(doc_dir, "README"), 'w') as f:
        f.write(readme_content)
    
    # Create changelog
    changelog_content = """pqc-vpn (1.0.0) stable; urgency=medium

  * Initial release
  * ML-DSA certificate chain support
  * GUI and CLI interfaces
  * Debug5 mode for detailed analysis

 -- PQC VPN Team <support@pqcvpn.org>  """ + subprocess.check_output(['date', '-R']).decode().strip() + """
"""
    
    with open(os.path.join(doc_dir, "changelog"), 'w') as f:
        f.write(changelog_content)
    
    print("Created documentation files")

def create_icon(debian_dir):
    """Create a simple icon for the application"""
    # Create a simple SVG icon
    svg_content = """<?xml version="1.0" encoding="UTF-8"?>
<svg width="48" height="48" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg">
  <rect width="48" height="48" rx="8" fill="#2E3440"/>
  <circle cx="24" cy="16" r="6" fill="#5E81AC" stroke="#ECEFF4" stroke-width="2"/>
  <circle cx="12" cy="32" r="4" fill="#88C0D0" stroke="#ECEFF4" stroke-width="1"/>
  <circle cx="36" cy="32" r="4" fill="#88C0D0" stroke="#ECEFF4" stroke-width="1"/>
  <line x1="24" y1="22" x2="12" y2="28" stroke="#ECEFF4" stroke-width="2"/>
  <line x1="24" y1="22" x2="36" y2="28" stroke="#ECEFF4" stroke-width="2"/>
  <text x="24" y="42" text-anchor="middle" fill="#ECEFF4" font-family="sans-serif" font-size="8" font-weight="bold">PQC</text>
</svg>"""
    
    icon_file = os.path.join(debian_dir, "usr", "share", "pixmaps", "pqc-vpn.svg")
    with open(icon_file, 'w') as f:
        f.write(svg_content)
    
    print("Created application icon")

def build_deb_package(debian_dir, package_name, version):
    """Build the .deb package"""
    print("Building .deb package...")
    
    try:
        # Build the package
        parent_dir = os.path.dirname(debian_dir)
        package_dir_name = os.path.basename(debian_dir)
        
        cmd = ['dpkg-deb', '--build', package_dir_name]
        result = subprocess.run(cmd, cwd=parent_dir, capture_output=True, text=True)
        
        if result.returncode == 0:
            deb_file = f"{debian_dir}.deb"
            final_deb = f"{package_name}_{version}_all.deb"
            
            if os.path.exists(deb_file):
                shutil.move(deb_file, final_deb)
                print(f"✅ Package built successfully: {final_deb}")
                return True
            else:
                print("❌ Package file not found after build")
                return False
        else:
            print("❌ Package build failed:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ Build error: {e}")
        return False

def main():
    """Main build function"""
    print("🔨 Building Ubuntu .deb package for PQC VPN...")
    print("=" * 50)
    
    # Check if we're on a system that can build .deb packages
    if not shutil.which('dpkg-deb'):
        print("❌ dpkg-deb not found. Please install dpkg-dev:")
        print("   sudo apt install dpkg-dev")
        return False
    
    # Create temporary build directory
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"Using build directory: {temp_dir}")
        
        # Create package structure
        debian_dir, package_name, version = create_debian_structure(temp_dir)
        
        # Create package files
        create_control_file(debian_dir, package_name, version)
        create_postinst_script(debian_dir)
        create_prerm_script(debian_dir)
        create_desktop_file(debian_dir)
        create_launcher_scripts(debian_dir)
        copy_application_files(debian_dir)
        create_icon(debian_dir)
        
        # Build the package
        if build_deb_package(debian_dir, package_name, version):
            print("\n✅ Ubuntu package created successfully!")
            print(f"\nPackage: {package_name}_{version}_all.deb")
            print("\nTo install:")
            print(f"  sudo dpkg -i {package_name}_{version}_all.deb")
            print("  sudo apt-get install -f  # Fix any dependency issues")
            
            print("\nTo uninstall:")
            print(f"  sudo apt remove {package_name}")
            
            return True
        else:
            print("\n❌ Package build failed!")
            return False

if __name__ == "__main__":
    main()
