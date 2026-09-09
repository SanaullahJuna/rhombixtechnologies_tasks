#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Rhombix Technologies - Professional Bug Bounty Toolkit
Version 2.0
Author: [Your Name]
Description: A comprehensive vulnerability scanner with real‑time file‑based logging.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, font
import socket
import requests
import threading
import ssl
import datetime
import time
import os
import json
import queue
import concurrent.futures
from urllib.parse import urlparse
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------------- Constants ---------------------------------
VERSION = "2.0"
APP_NAME = "Rhombix Bug Bounty Toolkit"
LOG_FILE = "scan_log.txt"  # All logs are written here immediately
CONFIG_FILE = "config.json"

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                 1723, 3306, 3389, 5900, 8080, 8443]

DEFAULT_SUBDOMAINS = ['www', 'mail', 'ftp', 'admin', 'dev', 'api', 'test', 'staging',
                      'blog', 'shop', 'support', 'vpn', 'remote', 'docs', 'portal']

DEFAULT_DIRS = ['admin', 'login', 'wp-admin', 'dashboard', 'backup', 'config',
                'hidden', 'uploads', 'images', 'js', 'css', 'api/v1', 'test',
                'tmp', 'logs', 'private']

# -------------------------------- Logger Class --------------------------------
class Logger:
    """
    Thread‑safe logger that writes every message to a file immediately
    and also updates the GUI text widget via a queue.
    """
    def __init__(self, log_file=LOG_FILE, max_lines=10000):
        self.log_file = log_file
        self.max_lines = max_lines
        self.lock = threading.Lock()
        self.gui_queue = queue.Queue()
        self._init_log_file()

    def _init_log_file(self):
        """Create/clear the log file on startup."""
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write("")  # truncate

    def log(self, message, display=True):
        """
        Append a message to the log file and optionally add it to the GUI queue.
        Thread‑safe.
        """
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}"
        with self.lock:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(formatted + "\n")
        if display:
            self.gui_queue.put(formatted)

    def get_all_lines(self):
        """Return a list of all lines in the log file."""
        with self.lock:
            try:
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    return f.read().splitlines()
            except FileNotFoundError:
                return []

    def clear(self):
        """Truncate the log file and empty the GUI queue."""
        with self.lock:
            with open(self.log_file, 'w', encoding='utf-8') as f:
                f.write("")
        while not self.gui_queue.empty():
            try:
                self.gui_queue.get_nowait()
            except queue.Empty:
                break

    def get_gui_messages(self):
        """Retrieve all queued GUI messages (non‑blocking)."""
        messages = []
        while not self.gui_queue.empty():
            try:
                messages.append(self.gui_queue.get_nowait())
            except queue.Empty:
                break
        return messages

# -------------------------------- Config Manager -------------------------------
class ConfigManager:
    """Load and save user settings."""
    def __init__(self, config_file=CONFIG_FILE):
        self.config_file = config_file
        self.defaults = {
            'ports': DEFAULT_PORTS,
            'subdomains': DEFAULT_SUBDOMAINS,
            'directories': DEFAULT_DIRS,
            'threads': 20,
            'port_timeout': 1.5,
            'http_timeout': 5,
            'target_url': 'http://neverssl.com',
            'scan_ssl': True,
            'scan_ports': True,
            'scan_subdomains': True,
            'scan_dirs': True,
            'scan_headers': True
        }
        self.data = self.load()

    def load(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return self.defaults.copy()
        return self.defaults.copy()

    def save(self):
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=4)

    def get(self, key):
        return self.data.get(key, self.defaults.get(key))

    def set(self, key, value):
        self.data[key] = value

# -------------------------------- Scanner Core --------------------------------
class ScannerCore:
    """
    Implements all scanning modules. Uses the Logger for output.
    """
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.target_url = ""
        self.domain = ""
        self.scheme = "http"
        self.results = {}

    def set_target(self, url):
        self.target_url = url
        parsed = urlparse(url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme

    def run_full_scan(self, callback=None):
        """
        Execute all selected scan modules.
        callback: function to call when each module finishes (for GUI updates).
        """
        self.logger.log("=" * 60)
        self.logger.log(f"🛡️ Starting Bug Bounty Scan for: {self.target_url}")
        self.logger.log("=" * 60)

        # 0. DNS Resolution
        self.logger.log(f"\n[0] Resolving Domain: {self.domain}")
        try:
            ip = socket.gethostbyname(self.domain)
            self.logger.log(f"   ✅ Resolved to IP: {ip}")
        except Exception as e:
            self.logger.log(f"   ❌ DNS Resolution Failed: {str(e)}")
            self.logger.log("❌ Aborting scan due to DNS failure.")
            return

        # 1. SSL Check (if HTTPS)
        if self.scheme == "https" and self.config.get('scan_ssl'):
            self.check_ssl()

        # 2. Port Scan
        if self.config.get('scan_ports'):
            self.scan_ports_parallel()

        # 3. Subdomain Enumeration
        if self.config.get('scan_subdomains'):
            self.find_subdomains()

        # 4. Directory Bruteforce
        if self.config.get('scan_dirs'):
            self.bruteforce_dirs()

        # 5. Security Headers
        if self.config.get('scan_headers'):
            self.check_headers()

        self.logger.log("\n" + "=" * 60)
        self.logger.log("✅ Scan Completed Successfully!")
        self.logger.log("=" * 60)

        if callback:
            callback()

    def check_ssl(self):
        self.logger.log("\n[1] SSL Certificate Check")
        try:
            hostname = self.domain
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                if cert is None:
                    self.logger.log("   ℹ️ No certificate returned.")
                    return
                expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.datetime.now()).days
                self.logger.log(f"   ✅ Valid until: {expiry.strftime('%Y-%m-%d')} ({days_left} days left)")
        except Exception as e:
            self.logger.log(f"   ⚠️ SSL check failed: {str(e)[:50]}")

    def scan_ports_parallel(self):
        port_list = self.config.get('ports')
        self.logger.log(f"\n[2] Port Scan ({len(port_list)} ports, parallel)")
        open_ports = []

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.get('port_timeout'))
                result = sock.connect_ex((self.domain, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    return (port, service)
                sock.close()
            except:
                pass
            return None

        max_workers = self.config.get('threads')
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_port, p): p for p in port_list}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    port, service = res
                    self.logger.log(f"   🔓 Port {port} is OPEN ({service})")
                    open_ports.append(str(port))

        if not open_ports:
            self.logger.log("   ℹ️ No open ports found.")
        else:
            self.logger.log(f"   📊 Found {len(open_ports)} open ports.")

    def find_subdomains(self):
        sub_list = self.config.get('subdomains')
        self.logger.log(f"\n[3] Subdomain Enumeration ({len(sub_list)} candidates)")
        found = []
        for sub in sub_list:
            target = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(target)
                self.logger.log(f"   ✅ Found: {target}")
                found.append(target)
            except:
                pass
        if not found:
            self.logger.log("   ℹ️ No subdomains found.")

    def bruteforce_dirs(self):
        dir_list = self.config.get('directories')
        self.logger.log(f"\n[4] Directory Bruteforce ({len(dir_list)} paths)")
        base = self.target_url
        found_any = False
        timeout = self.config.get('http_timeout')
        for d in dir_list:
            url = f"{base}/{d}"
            try:
                resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200:
                    self.logger.log(f"   📂 Found: {url} (Status 200)")
                    found_any = True
                elif resp.status_code in [403, 401, 405]:
                    self.logger.log(f"   🔒 Restricted: {url} (Status {resp.status_code})")
                    found_any = True
            except:
                pass
        if not found_any:
            self.logger.log("   ℹ️ No accessible directories found.")

    def check_headers(self):
        self.logger.log("\n[5] Security Headers Analysis")
        try:
            resp = requests.get(self.target_url, timeout=self.config.get('http_timeout'),
                                verify=False, allow_redirects=True)
            headers = resp.headers
            security_checks = {
                'X-Frame-Options': 'Prevents Clickjacking',
                'X-Content-Type-Options': 'Prevents MIME sniffing',
                'Strict-Transport-Security': 'Enforces HTTPS (HSTS)',
                'Content-Security-Policy': 'Prevents XSS (CSP)',
                'Referrer-Policy': 'Controls referrer info'
            }
            missing = []
            for hdr, desc in security_checks.items():
                if hdr in headers:
                    self.logger.log(f"   ✅ {hdr} is present.")
                else:
                    self.logger.log(f"   ❌ {hdr} is MISSING! ({desc})")
                    missing.append(hdr)
            if not missing:
                self.logger.log("   🏆 All major security headers are present!")
        except Exception as e:
            self.logger.log(f"   ⚠️ Could not fetch headers: {str(e)[:60]}")

# -------------------------------- Main GUI Application -------------------------
class BugBountyApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{VERSION}")
        self.root.geometry("950x700")
        self.root.minsize(800, 600)

        # Initialize Logger and Config
        self.logger = Logger()
        self.config = ConfigManager()

        # Scanner core
        self.scanner = ScannerCore(self.logger, self.config)

        # Build GUI
        self._create_menu()
        self._create_notebook()
        self._create_statusbar()

        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Start GUI log updater
        self._update_gui_logs()

    # ---------------------------- GUI Construction ----------------------------
    def _create_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Generate Report", command=self.generate_report)
        file_menu.add_command(label="Clear Logs", command=self.clear_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Save Configuration", command=self.save_config)
        tools_menu.add_command(label="Load Configuration", command=self.load_config)
        tools_menu.add_separator()
        tools_menu.add_command(label="Reset to Defaults", command=self.reset_config)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    def _create_notebook(self):
        """Main tabbed interface."""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # ---- Scan Tab ----
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="Scan")

        # Target entry
        top_frame = tk.Frame(scan_frame)
        top_frame.pack(fill=tk.X, pady=5)
        tk.Label(top_frame, text="Target URL:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.target_var = tk.StringVar(value=self.config.get('target_url'))
        self.target_entry = tk.Entry(top_frame, textvariable=self.target_var, width=60, font=("Arial", 10))
        self.target_entry.pack(side=tk.LEFT, padx=10)

        self.scan_btn = tk.Button(top_frame, text="▶ Start Scan", command=self.start_scan,
                                  bg="#28a745", fg="white", font=("Arial", 10, "bold"), padx=15, pady=5)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(top_frame, text="⏹ Stop", command=self.stop_scan,
                                  bg="#dc3545", fg="white", font=("Arial", 10), padx=15, pady=5, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Progress bar and status
        progress_frame = tk.Frame(scan_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        self.progress = ttk.Progressbar(progress_frame, length=400, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        self.status_label = tk.Label(progress_frame, text="Ready", font=("Arial", 9))
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # Log display
        log_frame = tk.Frame(scan_frame)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        tk.Label(log_frame, text="Scan Log (live)", font=("Arial", 10, "bold")).pack(anchor='w')
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=("Consolas", 9),
                                                  bg="#f8f9fa", height=25)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # ---- Settings Tab ----
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")

        # Ports
        tk.Label(settings_frame, text="Custom Ports (comma separated):", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.ports_entry = tk.Entry(settings_frame, width=80)
        self.ports_entry.grid(row=0, column=1, padx=10, pady=5)
        self.ports_entry.insert(0, ",".join(map(str, self.config.get('ports'))))

        # Subdomains
        tk.Label(settings_frame, text="Subdomain Wordlist (comma separated):", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky='w', padx=10, pady=5)
        self.sub_entry = tk.Entry(settings_frame, width=80)
        self.sub_entry.grid(row=1, column=1, padx=10, pady=5)
        self.sub_entry.insert(0, ",".join(self.config.get('subdomains')))

        # Directories
        tk.Label(settings_frame, text="Directory Wordlist (comma separated):", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky='w', padx=10, pady=5)
        self.dir_entry = tk.Entry(settings_frame, width=80)
        self.dir_entry.grid(row=2, column=1, padx=10, pady=5)
        self.dir_entry.insert(0, ",".join(self.config.get('directories')))

        # Threads
        tk.Label(settings_frame, text="Threads (1-50):", font=("Arial", 10, "bold")).grid(row=3, column=0, sticky='w', padx=10, pady=5)
        self.threads_spin = tk.Spinbox(settings_frame, from_=1, to=50, width=10)
        self.threads_spin.grid(row=3, column=1, sticky='w', padx=10, pady=5)
        self.threads_spin.delete(0, tk.END)
        self.threads_spin.insert(0, str(self.config.get('threads')))

        # Timeouts
        tk.Label(settings_frame, text="Port Timeout (seconds):", font=("Arial", 10, "bold")).grid(row=4, column=0, sticky='w', padx=10, pady=5)
        self.port_timeout_entry = tk.Entry(settings_frame, width=10)
        self.port_timeout_entry.grid(row=4, column=1, sticky='w', padx=10, pady=5)
        self.port_timeout_entry.insert(0, str(self.config.get('port_timeout')))

        tk.Label(settings_frame, text="HTTP Timeout (seconds):", font=("Arial", 10, "bold")).grid(row=5, column=0, sticky='w', padx=10, pady=5)
        self.http_timeout_entry = tk.Entry(settings_frame, width=10)
        self.http_timeout_entry.grid(row=5, column=1, sticky='w', padx=10, pady=5)
        self.http_timeout_entry.insert(0, str(self.config.get('http_timeout')))

        # Scan modules checkboxes
        tk.Label(settings_frame, text="Scan Modules:", font=("Arial", 10, "bold")).grid(row=6, column=0, sticky='w', padx=10, pady=5)
        module_frame = tk.Frame(settings_frame)
        module_frame.grid(row=6, column=1, sticky='w', padx=10, pady=5)
        self.scan_ssl_var = tk.BooleanVar(value=self.config.get('scan_ssl'))
        self.scan_ports_var = tk.BooleanVar(value=self.config.get('scan_ports'))
        self.scan_sub_var = tk.BooleanVar(value=self.config.get('scan_subdomains'))
        self.scan_dirs_var = tk.BooleanVar(value=self.config.get('scan_dirs'))
        self.scan_headers_var = tk.BooleanVar(value=self.config.get('scan_headers'))

        tk.Checkbutton(module_frame, text="SSL Check", variable=self.scan_ssl_var).pack(anchor='w')
        tk.Checkbutton(module_frame, text="Port Scan", variable=self.scan_ports_var).pack(anchor='w')
        tk.Checkbutton(module_frame, text="Subdomain Enumeration", variable=self.scan_sub_var).pack(anchor='w')
        tk.Checkbutton(module_frame, text="Directory Bruteforce", variable=self.scan_dirs_var).pack(anchor='w')
        tk.Checkbutton(module_frame, text="Security Headers", variable=self.scan_headers_var).pack(anchor='w')

        # Save Settings button
        tk.Button(settings_frame, text="💾 Save Settings", command=self.save_settings,
                  bg="#17a2b8", fg="white", font=("Arial", 10, "bold"), padx=15, pady=5).grid(row=7, column=0, columnspan=2, pady=20)

        # ---- About Tab ----
        about_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_frame, text="About")
        about_text = f"""
        {APP_NAME} v{VERSION}

        Developed for Rhombix Technologies Internship
        Task 1: Bug Bounty Scanner

        Features:
        • Multi‑threaded port scanning
        • Subdomain enumeration
        • Directory bruteforcing
        • Security headers analysis
        • SSL certificate checking
        • Real‑time file‑based logging
        • Configurable settings

        © 2026 Rhombix Technologies
        """
        tk.Label(about_frame, text=about_text, justify=tk.LEFT, font=("Arial", 10)).pack(padx=20, pady=20)

    def _create_statusbar(self):
        self.statusbar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.statusbar.pack(side=tk.BOTTOM, fill=tk.X)

    # ---------------------------- GUI Update Loop ----------------------------
    def _update_gui_logs(self):
        """Periodically fetch queued log messages and display them."""
        messages = self.logger.get_gui_messages()
        for msg in messages:
            self.log_text.insert(tk.END, msg + "\n")
            self.log_text.see(tk.END)
        self.root.after(200, self._update_gui_logs)

    # ---------------------------- Scan Control ----------------------------
    def start_scan(self):
        if hasattr(self, '_scan_thread') and self._scan_thread and self._scan_thread.is_alive():
            messagebox.showinfo("Scan in progress", "A scan is already running.")
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL.")
            return
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        # Update config with current settings
        self._update_config_from_ui()

        # Clear logs
        self.logger.clear()
        self.log_text.delete(1.0, tk.END)

        # Set target in scanner
        self.scanner.set_target(target)
        self.config.set('target_url', target)

        # Disable UI elements
        self.scan_btn.config(state=tk.DISABLED, bg="#6c757d")
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start(10)
        self.status_label.config(text="Scanning...")

        # Start scan in background thread
        self._scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self._scan_thread.start()

    def _scan_worker(self):
        try:
            self.scanner.run_full_scan(callback=self._scan_finished)
        except Exception as e:
            self.logger.log(f"❌ Scan error: {str(e)}")
        finally:
            self.root.after(0, self._scan_finished)

    def _scan_finished(self):
        self.progress.stop()
        self.scan_btn.config(state=tk.NORMAL, bg="#28a745")
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Scan completed.")
        self.logger.log("✅ Scan finished successfully.")

    def stop_scan(self):
        # Not implemented – would require graceful thread interruption
        self.status_label.config(text="Stop requested (will finish current module)")
        # For simplicity, we just disable the button
        self.stop_btn.config(state=tk.DISABLED)

    # ---------------------------- Settings Management ----------------------------
    def _update_config_from_ui(self):
        """Read values from settings widgets and update config."""
        try:
            ports = [int(p.strip()) for p in self.ports_entry.get().split(',') if p.strip()]
            self.config.set('ports', ports)
            subdomains = [s.strip() for s in self.sub_entry.get().split(',') if s.strip()]
            self.config.set('subdomains', subdomains)
            dirs = [d.strip() for d in self.dir_entry.get().split(',') if d.strip()]
            self.config.set('directories', dirs)
            threads = int(self.threads_spin.get())
            self.config.set('threads', threads)
            port_timeout = float(self.port_timeout_entry.get())
            self.config.set('port_timeout', port_timeout)
            http_timeout = float(self.http_timeout_entry.get())
            self.config.set('http_timeout', http_timeout)
            self.config.set('scan_ssl', self.scan_ssl_var.get())
            self.config.set('scan_ports', self.scan_ports_var.get())
            self.config.set('scan_subdomains', self.scan_sub_var.get())
            self.config.set('scan_dirs', self.scan_dirs_var.get())
            self.config.set('scan_headers', self.scan_headers_var.get())
        except Exception as e:
            messagebox.showerror("Error", f"Invalid setting: {str(e)}")

    def save_settings(self):
        self._update_config_from_ui()
        self.config.save()
        messagebox.showinfo("Success", "Settings saved to disk.")

    def save_config(self):
        self.config.save()
        messagebox.showinfo("Success", "Configuration saved.")

    def load_config(self):
        self.config.load()
        self._populate_ui_from_config()
        messagebox.showinfo("Success", "Configuration loaded.")

    def reset_config(self):
        self.config.data = self.config.defaults.copy()
        self._populate_ui_from_config()
        self.config.save()
        messagebox.showinfo("Success", "Reset to default settings.")

    def _populate_ui_from_config(self):
        self.ports_entry.delete(0, tk.END)
        self.ports_entry.insert(0, ",".join(map(str, self.config.get('ports'))))
        self.sub_entry.delete(0, tk.END)
        self.sub_entry.insert(0, ",".join(self.config.get('subdomains')))
        self.dir_entry.delete(0, tk.END)
        self.dir_entry.insert(0, ",".join(self.config.get('directories')))
        self.threads_spin.delete(0, tk.END)
        self.threads_spin.insert(0, str(self.config.get('threads')))
        self.port_timeout_entry.delete(0, tk.END)
        self.port_timeout_entry.insert(0, str(self.config.get('port_timeout')))
        self.http_timeout_entry.delete(0, tk.END)
        self.http_timeout_entry.insert(0, str(self.config.get('http_timeout')))
        self.scan_ssl_var.set(self.config.get('scan_ssl'))
        self.scan_ports_var.set(self.config.get('scan_ports'))
        self.scan_sub_var.set(self.config.get('scan_subdomains'))
        self.scan_dirs_var.set(self.config.get('scan_dirs'))
        self.scan_headers_var.set(self.config.get('scan_headers'))
        self.target_var.set(self.config.get('target_url'))

    # ---------------------------- Report Generation ----------------------------
    def generate_report(self):
        """Read the log file and save as report."""
        lines = self.logger.get_all_lines()
        if not lines:
            messagebox.showwarning("No Data", "No scan logs found.\nRun a scan first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not file_path:
            return

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("Rhombix Technologies - Bug Bounty Report\n")
                f.write("=" * 70 + "\n")
                f.write(f"Target: {self.target_var.get()}\n")
                f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 70 + "\n\n")
                for line in lines:
                    f.write(line + "\n")
                f.write("\n" + "=" * 70 + "\n")
                f.write("End of Report\n")
                f.write("=" * 70)
            messagebox.showinfo("Success", f"Report saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")

    def clear_logs(self):
        self.logger.clear()
        self.log_text.delete(1.0, tk.END)

    # ---------------------------- Misc ----------------------------
    def show_about(self):
        messagebox.showinfo("About",
            f"{APP_NAME} v{VERSION}\n\n"
            "A professional bug bounty scanning tool.\n"
            "Developed for Rhombix Technologies Internship.\n\n"
            "© 2026 Rhombix Technologies")

    def _on_close(self):
        self.config.save()
        self.root.destroy()

# -------------------------------- Main ---------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = BugBountyApp(root)
    root.mainloop()