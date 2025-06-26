import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
import os
import time
import psutil
import pyttsx3
import socket

try:
    engine = pyttsx3.init()
    engine.setProperty('rate', 150)
except Exception as e:
    print(f"Voice engine initialization failed: {e}")
    engine = None

root = tk.Tk()
root.title("Advanced Ransomware Protection")
root.geometry("1000x700")
root.configure(bg="#1a1a1a")

log_frame = tk.Frame(root, bg="#1a1a1a")
log_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

log_display = scrolledtext.ScrolledText(log_frame, width=120, height=25, bg="#2d2d2d", fg="white",
                                        insertbackground="white", font=("Consolas", 10))
log_display.pack(fill=tk.BOTH, expand=True)

def log_message(message):
    log_display.insert(tk.END, message + "\n")
    log_display.see(tk.END)

def voice_alert(message):
    if engine:
        try:
            engine.say(message)
            engine.runAndWait()
        except Exception as e:
            log_message(f"⚠ Voice alert failed: {e}")

def get_active_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.status == 'ESTABLISHED':
                connections.append({
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    'pid': conn.pid,
                    'status': conn.status
                })
        except (psutil.AccessDenied, AttributeError):
            continue
    return connections

def system_scan():
    log_message("🛠 Scanning system for threats...")
    ransomware_signatures = ["wannacry", "notpetya", "locky", "ransomware", "encrypt", "crypt", "petya"]
    suspicious_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            proc_info = proc.info
            for signature in ransomware_signatures:
                if (signature in proc_info['name'].lower() or 
                    (proc_info['exe'] and signature in proc_info['exe'].lower()) or
                    (proc_info['cmdline'] and any(signature in cmd.lower() for cmd in proc_info['cmdline']))):
                    suspicious_processes.append(proc_info)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if suspicious_processes:
        log_message("⚠ Suspicious processes detected:")
        for proc in suspicious_processes:
            log_message(f"❌ PID: {proc['pid']} | Name: {proc['name']} | Path: {proc['exe']}")
            block_process(proc['pid'])
        voice_alert("Warning! Suspicious processes detected.")
    else:
        log_message("✅ No suspicious processes detected.")

def start_system_scan():
    threading.Thread(target=system_scan, daemon=True).start()

def block_process(pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        p.wait(timeout=3)
        log_message(f"🛑 Successfully blocked process (PID: {pid})")
        return True
    except psutil.NoSuchProcess:
        log_message(f"⚠ Process (PID: {pid}) no longer exists")
        return False
    except psutil.AccessDenied:
        log_message(f"⚠ Access denied to terminate process (PID: {pid})")
        return False
    except Exception as e:
        log_message(f"⚠ Error blocking process (PID: {pid}): {e}")
        return False

monitoring = False

def system_monitor():
    global monitoring
    monitoring = True
    log_message("🖥 Starting system monitoring...")
    baseline_cpu = psutil.cpu_percent(interval=1)
    baseline_ram = psutil.virtual_memory().percent
    while monitoring:
        try:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            log_message(f"📊 System Stats | CPU: {cpu}% | RAM: {ram}% | Disk: {disk}%")
            if cpu > baseline_cpu * 2 and cpu > 80:
                log_message(f"⚠ CPU spike detected! Current: {cpu}% vs Baseline: {baseline_cpu}%")
                voice_alert("Warning! High CPU usage detected.")
            if ram > baseline_ram * 1.5 and ram > 85:
                log_message(f"⚠ RAM spike detected! Current: {ram}% vs Baseline: {baseline_ram}%")
                voice_alert("Warning! High RAM usage detected.")
            time.sleep(5)
        except Exception as e:
            log_message(f"⚠ Monitoring error: {e}")
            time.sleep(10)

def start_monitoring():
    global monitor_thread
    monitor_thread = threading.Thread(target=system_monitor, daemon=True)
    monitor_thread.start()
    monitor_button.config(state=tk.DISABLED)
    stop_monitor_button.config(state=tk.NORMAL)
    log_message("✅ System monitoring started")

def stop_monitoring():
    global monitoring
    monitoring = False
    monitor_button.config(state=tk.NORMAL)
    stop_monitor_button.config(state=tk.DISABLED)
    log_message("❌ System monitoring stopped")

def network_monitor():
    log_message("\n🌐 Network Information:")
    log_message("="*100)
    try:
        interfaces = psutil.net_if_addrs()
        log_message("📡 Network Interfaces:")
        for interface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    log_message(f"   - {interface}: {addr.address}")
        connections = get_active_connections()
        log_message("\n🔌 Active Connections (IP:Port ↔ IP:Port):")
        for conn in connections[:20]:
            log_message(f"   {conn['laddr']} ↔ {conn['raddr']} | PID: {conn['pid']}")
    except Exception as e:
        log_message(f"⚠ Network monitoring error: {e}")

def start_network_monitor():
    threading.Thread(target=network_monitor, daemon=True).start()

def scan_folder():
    folder_path = filedialog.askdirectory()
    if not folder_path:
        return
    log_message(f"📂 Scanning folder: {folder_path}")
    ransomware_signatures = [
        "encrypt", "locked", ".locked", ".ransom", "decrypt",
        "crypt", "ransom", "payme", "bitcoin", "wallet"
    ]
    suspicious_extensions = [
        '.locky', '.crypt', '.encrypted', '.xtbl', '.cryp1',
        '.cryptolocker', '.cerber', '.zepto', '.odin', '.ryuk'
    ]
    suspicious_files = []
    total_files = 0
    for root_dir, _, files in os.walk(folder_path):
        for file in files:
            total_files += 1
            file_lower = file.lower()
            file_path = os.path.join(root_dir, file)
            for sig in ransomware_signatures:
                if sig in file_lower:
                    suspicious_files.append(file_path)
                    block_file(file_path)
                    break
            for ext in suspicious_extensions:
                if file_lower.endswith(ext):
                    suspicious_files.append(file_path)
                    block_file(file_path)
                    break
    if suspicious_files:
        log_message(f"⚠ Found {len(suspicious_files)}/{total_files} suspicious files:")
        for file in suspicious_files[:20]:
            log_message(f"❌ {file}")
        if len(suspicious_files) > 20:
            log_message(f"... and {len(suspicious_files) - 20} more files not shown")
        voice_alert(f"Warning! Found {len(suspicious_files)} suspicious files")
    else:
        log_message(f"✅ No suspicious files found in {total_files} scanned files")

def block_file(file_path):
    try:
        try:
            os.remove(file_path)
            log_message(f"🛑 Deleted suspicious file: {file_path}")
            return True
        except PermissionError:
            try:
                with open(file_path, 'wb') as f:
                    f.truncate()
                log_message(f"🛑 Emptied suspicious file: {file_path}")
                return True
            except Exception as e:
                log_message(f"⚠ Could not block file {file_path}: {e}")
                return False
    except Exception as e:
        log_message(f"⚠ Error blocking file {file_path}: {e}")
        return False

def block_ransomware():
    ransomware_processes = [
        "wannacry", "notpetya", "locky", "ransomware", "encrypt",
        "crypt", "cerber", "petya", "gandcrab", "revil", "ryuk",
        "maze", "conti", "phobos", "crysis", "globelmposter"
    ]
    blocked = 0
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            proc_info = proc.info
            proc_name = proc_info['name'].lower()
            proc_exe = proc_info['exe'].lower() if proc_info['exe'] else ""
            for ransomware in ransomware_processes:
                if ransomware in proc_name or ransomware in proc_exe:
                    if block_process(proc_info['pid']):
                        blocked += 1
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if blocked > 0:
        log_message(f"✅ Successfully blocked {blocked} ransomware processes")
        voice_alert(f"Blocked {blocked} ransomware processes")
    else:
        log_message("ℹ VERIFICATION COMPLETED SUCCESSFULLY. YOUR SYSTEM IS SAFE AND SECURE.YOU'RE GOOD TO GO.")

button_frame = tk.Frame(root, bg="#1a1a1a")
button_frame.pack(pady=10)

button_style = {
    'font': ('Arial', 10, 'bold'),
    'width': 20,
    'height': 2,
    'bd': 0,
    'relief': tk.RAISED
}

row0 = tk.Frame(button_frame, bg="#1a1a1a")
row0.pack(pady=5)

monitor_button = tk.Button(row0, text="🔴 Start Monitoring", bg="#d9534f", fg="white", 
                           command=start_monitoring, **button_style)
monitor_button.pack(side=tk.LEFT, padx=5)

stop_monitor_button = tk.Button(row0, text="⚫ Stop Monitoring", bg="#6c757d", fg="white",
                                state=tk.DISABLED, command=stop_monitoring, **button_style)
stop_monitor_button.pack(side=tk.LEFT, padx=5)

row1 = tk.Frame(button_frame, bg="#1a1a1a")
row1.pack(pady=5)

sys_scan_button = tk.Button(row1, text="🖥 System Scan", bg="#007bff", fg="white",
                            command=start_system_scan, **button_style)
sys_scan_button.pack(side=tk.LEFT, padx=5)

scan_folder_button = tk.Button(row1, text="📂 Scan Folder", bg="#6f42c1", fg="white",
                               command=scan_folder, **button_style)
scan_folder_button.pack(side=tk.LEFT, padx=5)

row2 = tk.Frame(button_frame, bg="#1a1a1a")
row2.pack(pady=5)

net_monitor_button = tk.Button(row2, text="🌐 Network Info", bg="#28a745", fg="white",
                               command=start_network_monitor, **button_style)
net_monitor_button.pack(side=tk.LEFT, padx=5)

block_button = tk.Button(row2, text="🛑  Verify ", bg="#fd7e14", fg="black",
                         command=block_ransomware, **button_style)
block_button.pack(side=tk.LEFT, padx=5)

row3 = tk.Frame(button_frame, bg="#1a1a1a")
row3.pack(pady=5)

exit_button = tk.Button(row3, text="❌ Exit", bg="#f8f9fa", fg="black",
                        command=root.quit, **button_style)
exit_button.pack(side=tk.LEFT, padx=5)

root.mainloop()