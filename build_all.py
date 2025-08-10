#!/usr/bin/env python3
"""
Unified Build Script for PQC VPN GUI Application
Builds both Windows .exe and Ubuntu .deb packages
"""

import os
import sys
import platform
import subprocess
import argparse

def main():
    """Main build function"""
    # Set UTF-8 encoding for Windows console
    if platform.system() == "Windows":
        os.system("chcp 65001 >nul 2>&1")
    
    parser = argparse.ArgumentParser(description="Build PQC VPN packages")
    parser.add_argument("--windows", action="store_true", help="Build Windows .exe")
    parser.add_argument("--ubuntu", action="store_true", help="Build Ubuntu .deb")
    parser.add_argument("--all", action="store_true", help="Build all packages")
    parser.add_argument("--test-gui", action="store_true", help="Test GUI application")
    
    args = parser.parse_args()
    
    if not any([args.windows, args.ubuntu, args.all, args.test_gui]):
        parser.print_help()
        return
    
    try:
        print("🔨 PQC VPN Package Builder")
    except UnicodeEncodeError:
        print("[BUILD] PQC VPN Package Builder")
    print("=" * 40)
    
    if args.test_gui:
        try:
            print("🧪 Testing GUI application...")
        except UnicodeEncodeError:
            print("[TEST] Testing GUI application...")
        test_gui()
    
    if args.windows or args.all:
        try:
            print("\n📦 Building Windows package...")
        except UnicodeEncodeError:
            print("\n[BUILD] Building Windows package...")
        build_windows()
    
    if args.ubuntu or args.all:
        try:
            print("\n📦 Building Ubuntu package...")
        except UnicodeEncodeError:
            print("\n[BUILD] Building Ubuntu package...")
        build_ubuntu()
    
    try:
        print("\n✅ Build process completed!")
    except UnicodeEncodeError:
        print("\n[SUCCESS] Build process completed!")

def test_gui():
    """Test the GUI application"""
    try:
        print("Starting GUI test...")
        # Import and test basic functionality
        import tkinter as tk
        
        # Test if GUI can be created
        root = tk.Tk()
        root.withdraw()  # Hide the window
        
        # Test importing our GUI module
        sys.path.insert(0, os.path.dirname(__file__))
        import pqc_vpn_gui
        
        try:
            print("✅ GUI application imports successfully")
            print("✅ Tkinter is available")
        except UnicodeEncodeError:
            print("[SUCCESS] GUI application imports successfully")
            print("[SUCCESS] Tkinter is available")
        
        root.destroy()
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ GUI test failed: {e}")

def build_windows():
    """Build Windows package"""
    try:
        result = subprocess.run([sys.executable, "build_windows.py"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Windows build completed")
            print(result.stdout)
        else:
            print("❌ Windows build failed")
            print(result.stderr)
            
    except Exception as e:
        print(f"❌ Windows build error: {e}")

def build_ubuntu():
    """Build Ubuntu package"""
    try:
        result = subprocess.run([sys.executable, "build_ubuntu.py"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Ubuntu build completed")
            print(result.stdout)
        else:
            print("❌ Ubuntu build failed")
            print(result.stderr)
            
    except Exception as e:
        print(f"❌ Ubuntu build error: {e}")

if __name__ == "__main__":
    main()
