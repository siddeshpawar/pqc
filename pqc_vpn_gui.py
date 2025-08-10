#!/usr/bin/env python3
"""
Post-Quantum Cryptography VPN GUI Application
Simple interface for configuring and running ML-DSA Certificate Chain VPN
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import threading
import subprocess
import json
from pathlib import Path
import time

class PQCVPNGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Post-Quantum Cryptography VPN")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Configuration variables
        self.local_ip = tk.StringVar(value="192.168.1.10")
        self.remote_ip = tk.StringVar(value="192.168.1.20")
        self.cert_dir = tk.StringVar(value="pqc_ipsec")
        self.role = tk.StringVar(value="initiator")
        self.debug_mode = tk.BooleanVar(value=False)
        
        # VPN process
        self.vpn_process = None
        self.is_running = False
        
        self.create_widgets()
        self.load_config()
        
    def create_widgets(self):
        """Create the GUI widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="🔐 Post-Quantum Cryptography VPN", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Configuration section
        config_frame = ttk.LabelFrame(main_frame, text="VPN Configuration", padding="10")
        config_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # IP Configuration
        ttk.Label(config_frame, text="Local IP:").grid(row=0, column=0, sticky=tk.W, pady=2)
        local_ip_entry = ttk.Entry(config_frame, textvariable=self.local_ip, width=20)
        local_ip_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(5, 10), pady=2)
        
        ttk.Label(config_frame, text="Remote IP:").grid(row=0, column=2, sticky=tk.W, pady=2)
        remote_ip_entry = ttk.Entry(config_frame, textvariable=self.remote_ip, width=20)
        remote_ip_entry.grid(row=0, column=3, sticky=(tk.W, tk.E), padx=5, pady=2)
        
        # Certificate Directory
        ttk.Label(config_frame, text="Certificate Directory:").grid(row=1, column=0, sticky=tk.W, pady=2)
        cert_dir_entry = ttk.Entry(config_frame, textvariable=self.cert_dir, width=30)
        cert_dir_entry.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=2)
        
        cert_browse_btn = ttk.Button(config_frame, text="Browse", command=self.browse_cert_dir)
        cert_browse_btn.grid(row=1, column=3, padx=5, pady=2)
        
        # Role Selection
        ttk.Label(config_frame, text="Role:").grid(row=2, column=0, sticky=tk.W, pady=2)
        role_frame = ttk.Frame(config_frame)
        role_frame.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Radiobutton(role_frame, text="Initiator", variable=self.role, 
                       value="initiator").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(role_frame, text="Responder", variable=self.role, 
                       value="responder").pack(side=tk.LEFT)
        
        # Debug Mode
        debug_check = ttk.Checkbutton(config_frame, text="Enable Debug5 Mode (Deep ML-DSA Analysis)", 
                                     variable=self.debug_mode)
        debug_check.grid(row=3, column=0, columnspan=4, sticky=tk.W, pady=10)
        
        # Certificate Validation
        cert_frame = ttk.LabelFrame(main_frame, text="Certificate Validation", padding="10")
        cert_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        validate_btn = ttk.Button(cert_frame, text="🔍 Validate Certificates", 
                                 command=self.validate_certificates)
        validate_btn.grid(row=0, column=0, pady=5)
        
        self.cert_status_label = ttk.Label(cert_frame, text="Certificate status: Not checked")
        self.cert_status_label.grid(row=0, column=1, padx=20, pady=5)
        
        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        self.start_btn = ttk.Button(control_frame, text="🚀 Start VPN", 
                                   command=self.start_vpn, style="Accent.TButton")
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="⏹ Stop VPN", 
                                  command=self.stop_vpn, state="disabled")
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        save_btn = ttk.Button(control_frame, text="💾 Save Config", command=self.save_config)
        save_btn.pack(side=tk.LEFT, padx=5)
        
        # Status and Log area
        log_frame = ttk.LabelFrame(main_frame, text="VPN Status & Logs", padding="5")
        log_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Status indicators
        status_frame = ttk.Frame(log_frame)
        status_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.status_label = ttk.Label(status_frame, text="Status: Stopped", 
                                     font=("Arial", 10, "bold"))
        self.status_label.pack(side=tk.LEFT)
        
        self.ike_status = ttk.Label(status_frame, text="IKE: ❌")
        self.ike_status.pack(side=tk.LEFT, padx=20)
        
        self.tunnel_status = ttk.Label(status_frame, text="Tunnel: ❌")
        self.tunnel_status.pack(side=tk.LEFT, padx=10)
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        config_frame.columnconfigure(1, weight=1)
        config_frame.columnconfigure(3, weight=1)
        log_frame.rowconfigure(1, weight=1)
        
    def browse_cert_dir(self):
        """Browse for certificate directory"""
        directory = filedialog.askdirectory(
            title="Select Certificate Directory",
            initialdir=self.cert_dir.get() if os.path.exists(self.cert_dir.get()) else os.getcwd()
        )
        if directory:
            self.cert_dir.set(directory)
            
    def validate_certificates(self):
        """Validate certificate directory and files"""
        cert_path = self.cert_dir.get()
        
        if not os.path.exists(cert_path):
            self.cert_status_label.config(text="❌ Certificate directory not found", foreground="red")
            self.log("ERROR: Certificate directory not found: " + cert_path)
            return False
            
        # Check for required subdirectories
        client_dir = os.path.join(cert_path, "client")
        server_dir = os.path.join(cert_path, "server")
        
        issues = []
        
        if not os.path.exists(client_dir):
            issues.append("Missing client/ subdirectory")
        else:
            # Check for certificate files in client directory
            cert_files = [f for f in os.listdir(client_dir) if f.endswith('.crt') or f.endswith('.pem')]
            if not cert_files:
                issues.append("No certificate files found in client/")
                
        if not os.path.exists(server_dir):
            issues.append("Missing server/ subdirectory")
        else:
            # Check for certificate files in server directory
            cert_files = [f for f in os.listdir(server_dir) if f.endswith('.crt') or f.endswith('.pem')]
            if not cert_files:
                issues.append("No certificate files found in server/")
        
        if issues:
            self.cert_status_label.config(text="⚠ Issues found", foreground="orange")
            self.log("Certificate validation issues:")
            for issue in issues:
                self.log("  - " + issue)
            return False
        else:
            self.cert_status_label.config(text="✅ Certificates valid", foreground="green")
            self.log("Certificate validation successful")
            return True
            
    def start_vpn(self):
        """Start the VPN process"""
        if self.is_running:
            return
            
        # Validate configuration
        if not self.validate_certificates():
            messagebox.showerror("Configuration Error", 
                               "Please fix certificate issues before starting VPN")
            return
            
        # Build command
        script_path = os.path.join(os.path.dirname(__file__), "pqc_vpn_certificate_working.py")
        if not os.path.exists(script_path):
            messagebox.showerror("Error", "VPN script not found: " + script_path)
            return
            
        cmd = [
            sys.executable, script_path,
            self.local_ip.get(),
            self.remote_ip.get(),
            self.cert_dir.get(),
            self.role.get()
        ]
        
        if self.debug_mode.get():
            cmd.append("debug5")
            
        self.log(f"Starting VPN with command: {' '.join(cmd)}")
        
        # Start VPN process in separate thread
        self.is_running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_label.config(text="Status: Starting...", foreground="orange")
        
        self.vpn_thread = threading.Thread(target=self.run_vpn, args=(cmd,))
        self.vpn_thread.daemon = True
        self.vpn_thread.start()
        
        # Start status monitoring
        self.monitor_status()
        
    def run_vpn(self, cmd):
        """Run VPN process"""
        try:
            self.vpn_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Read output line by line
            for line in iter(self.vpn_process.stdout.readline, ''):
                if line:
                    self.root.after(0, self.log, line.strip())
                    
            self.vpn_process.wait()
            
        except Exception as e:
            self.root.after(0, self.log, f"ERROR: Failed to start VPN: {e}")
        finally:
            self.root.after(0, self.vpn_stopped)
            
    def stop_vpn(self):
        """Stop the VPN process"""
        if self.vpn_process:
            try:
                self.vpn_process.terminate()
                self.log("VPN process terminated")
            except:
                pass
                
        self.vpn_stopped()
        
    def vpn_stopped(self):
        """Handle VPN process stopped"""
        self.is_running = False
        self.vpn_process = None
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Status: Stopped", foreground="red")
        self.ike_status.config(text="IKE: ❌")
        self.tunnel_status.config(text="Tunnel: ❌")
        
    def monitor_status(self):
        """Monitor VPN status"""
        if self.is_running:
            self.status_label.config(text="Status: Running", foreground="green")
            # Schedule next check
            self.root.after(5000, self.monitor_status)
            
    def log(self, message):
        """Add message to log"""
        timestamp = time.strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
        
        # Update status indicators based on log content
        if "IKE established" in message or "IKE: True" in message:
            self.ike_status.config(text="IKE: ✅", foreground="green")
        elif "Tunnel" in message and ("established" in message or "True" in message):
            self.tunnel_status.config(text="Tunnel: ✅", foreground="green")
            
    def save_config(self):
        """Save configuration to file"""
        config = {
            "local_ip": self.local_ip.get(),
            "remote_ip": self.remote_ip.get(),
            "cert_dir": self.cert_dir.get(),
            "role": self.role.get(),
            "debug_mode": self.debug_mode.get()
        }
        
        config_file = os.path.join(os.path.dirname(__file__), "pqc_vpn_config.json")
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            self.log("Configuration saved to " + config_file)
            messagebox.showinfo("Success", "Configuration saved successfully")
        except Exception as e:
            self.log(f"ERROR: Failed to save config: {e}")
            messagebox.showerror("Error", f"Failed to save configuration: {e}")
            
    def load_config(self):
        """Load configuration from file"""
        config_file = os.path.join(os.path.dirname(__file__), "pqc_vpn_config.json")
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    
                self.local_ip.set(config.get("local_ip", "192.168.1.10"))
                self.remote_ip.set(config.get("remote_ip", "192.168.1.20"))
                self.cert_dir.set(config.get("cert_dir", "pqc_ipsec"))
                self.role.set(config.get("role", "initiator"))
                self.debug_mode.set(config.get("debug_mode", False))
                
                self.log("Configuration loaded from " + config_file)
            except Exception as e:
                self.log(f"ERROR: Failed to load config: {e}")

def main():
    """Main function"""
    root = tk.Tk()
    
    # Set application icon (if available)
    try:
        # You can add an icon file here
        # root.iconbitmap("pqc_vpn.ico")
        pass
    except:
        pass
        
    app = PQCVPNGui(root)
    
    # Handle window closing
    def on_closing():
        if app.is_running:
            if messagebox.askokcancel("Quit", "VPN is running. Stop and quit?"):
                app.stop_vpn()
                root.destroy()
        else:
            root.destroy()
            
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Start the GUI
    root.mainloop()

if __name__ == "__main__":
    main()
