#!/usr/bin/env python3
"""
Windows Build Script for PQC VPN GUI Application
Creates a standalone .exe installer using PyInstaller
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_dependencies():
    """Check if required build dependencies are installed"""
    required_packages = ['pyinstaller', 'tkinter']
    missing = []
    
    for package in required_packages:
        try:
            if package == 'tkinter':
                import tkinter
            else:
                __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print("Missing required packages:")
        for pkg in missing:
            if pkg == 'pyinstaller':
                print(f"  Install with: pip install {pkg}")
            elif pkg == 'tkinter':
                print(f"  tkinter should be included with Python. Try: pip install tk")
        return False
    
    return True

def create_spec_file():
    """Create PyInstaller spec file"""
    spec_content = '''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['pqc_vpn_gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('pqc_vpn_certificate_working.py', '.'),
        ('*.json', '.'),
        ('*.md', '.'),
    ],
    hiddenimports=[
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.scrolledtext',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PQC-VPN',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='pqc_vpn.ico'  # Optional: add icon file
)
'''
    
    with open('pqc_vpn.spec', 'w') as f:
        f.write(spec_content)
    
    print("Created PyInstaller spec file: pqc_vpn.spec")

def create_installer_script():
    """Create NSIS installer script for Windows"""
    nsis_content = '''!define APP_NAME "Post-Quantum Cryptography VPN"
!define APP_VERSION "1.0.0"
!define APP_PUBLISHER "PQC VPN Team"
!define APP_URL "https://github.com/your-repo/pqc-vpn"
!define APP_EXE "PQC-VPN.exe"

; Main Install settings
Name "${APP_NAME}"
InstallDir "$PROGRAMFILES\\${APP_NAME}"
InstallDirRegKey HKLM "Software\\${APP_NAME}" ""
OutFile "PQC-VPN-Installer.exe"

; Use compression
SetCompressor LZMA

; Modern interface settings
!include "MUI2.nsh"

!define MUI_ABORTWARNING
!define MUI_ICON "pqc_vpn.ico"
!define MUI_UNICON "pqc_vpn.ico"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

; Install Section
Section "Main Application" SecMain
    SetOutPath "$INSTDIR"
    
    ; Copy files
    File "dist\\${APP_EXE}"
    File /nonfatal "README.md"
    File /nonfatal "LICENSE.txt"
    
    ; Create shortcuts
    CreateDirectory "$SMPROGRAMS\\${APP_NAME}"
    CreateShortCut "$SMPROGRAMS\\${APP_NAME}\\${APP_NAME}.lnk" "$INSTDIR\\${APP_EXE}"
    CreateShortCut "$DESKTOP\\${APP_NAME}.lnk" "$INSTDIR\\${APP_EXE}"
    
    ; Registry entries
    WriteRegStr HKLM "Software\\${APP_NAME}" "" "$INSTDIR"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APP_NAME}" "DisplayName" "${APP_NAME}"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APP_NAME}" "UninstallString" "$INSTDIR\\Uninstall.exe"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APP_NAME}" "DisplayVersion" "${APP_VERSION}"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APP_NAME}" "Publisher" "${APP_PUBLISHER}"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APP_NAME}" "URLInfoAbout" "${APP_URL}"
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\\Uninstall.exe"
SectionEnd

; Uninstall Section
Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\\${APP_EXE}"
    Delete "$INSTDIR\\README.md"
    Delete "$INSTDIR\\LICENSE.txt"
    Delete "$INSTDIR\\Uninstall.exe"
    
    ; Remove shortcuts
    Delete "$SMPROGRAMS\\${APP_NAME}\\${APP_NAME}.lnk"
    Delete "$DESKTOP\\${APP_NAME}.lnk"
    RMDir "$SMPROGRAMS\\${APP_NAME}"
    
    ; Remove registry entries
    DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APP_NAME}"
    DeleteRegKey HKLM "Software\\${APP_NAME}"
    
    ; Remove installation directory
    RMDir "$INSTDIR"
SectionEnd
'''
    
    with open('pqc_vpn_installer.nsi', 'w') as f:
        f.write(nsis_content)
    
    print("Created NSIS installer script: pqc_vpn_installer.nsi")

def create_license_file():
    """Create a simple license file"""
    license_content = '''MIT License

Copyright (c) 2024 Post-Quantum Cryptography VPN

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
    
    with open('LICENSE.txt', 'w') as f:
        f.write(license_content)
    
    print("Created LICENSE.txt")

def build_executable():
    """Build the executable using PyInstaller"""
    print("Building executable with PyInstaller...")
    
    try:
        # Clean previous builds
        if os.path.exists('dist'):
            shutil.rmtree('dist')
        if os.path.exists('build'):
            shutil.rmtree('build')
        
        # Build with PyInstaller
        cmd = [
            'pyinstaller',
            '--onefile',
            '--windowed',
            '--name=PQC-VPN',
            '--add-data=pqc_vpn_certificate_working.py;.',
            'pqc_vpn_gui.py'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Executable built successfully!")
            print("📁 Output: dist/PQC-VPN.exe")
            return True
        else:
            print("❌ Build failed:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ Build error: {e}")
        return False

def main():
    """Main build function"""
    print("🔨 Building Windows installer for PQC VPN...")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        print("\n❌ Missing dependencies. Please install them first.")
        return False
    
    # Create build files
    create_spec_file()
    create_installer_script()
    create_license_file()
    
    # Build executable
    if build_executable():
        print("\n✅ Build completed successfully!")
        print("\nFiles created:")
        print("  📦 dist/PQC-VPN.exe - Standalone executable")
        print("  🔧 pqc_vpn_installer.nsi - NSIS installer script")
        print("  📄 LICENSE.txt - License file")
        
        print("\nTo create installer:")
        print("  1. Install NSIS (https://nsis.sourceforge.io/)")
        print("  2. Right-click pqc_vpn_installer.nsi and select 'Compile NSIS Script'")
        print("  3. This will create PQC-VPN-Installer.exe")
        
        return True
    else:
        print("\n❌ Build failed!")
        return False

if __name__ == "__main__":
    main()
