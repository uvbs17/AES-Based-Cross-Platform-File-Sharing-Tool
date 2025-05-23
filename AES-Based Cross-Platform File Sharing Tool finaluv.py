#AES-Based Cross-Platform File Sharing Tooluv with compression, progress bar big file size support
#FInal


import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
import socket
import psutil
import os
import struct
import threading
import time
import json
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import zlib
from io import BytesIO

RECEIVED_DIR = 'received_files'
META_FILE = os.path.join(RECEIVED_DIR, 'metadata.json')

if not os.path.exists(RECEIVED_DIR):
    os.makedirs(RECEIVED_DIR)

if not os.path.exists(META_FILE):
    with open(META_FILE, 'w') as f:
        json.dump([], f)

def derive_key(password):
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def pad_data(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def log_message(message):
    log_viewer.insert(tk.END, message + "\n")
    log_viewer.see(tk.END)

def update_dashboard():
    for row in dashboard.get_children():
        dashboard.delete(row)
    with open(META_FILE, 'r') as f:
        records = json.load(f)
        for rec in records:
            if search_var.get().lower() in rec['name'].lower():
                dashboard.insert('', tk.END, values=(rec['name'], rec['size'], rec['timestamp']))

def delete_selected():
    selected = dashboard.selection()
    if selected:
        item = dashboard.item(selected[0])
        filename = item['values'][0]
        filepath = os.path.join(RECEIVED_DIR, filename)
        try:
            os.remove(filepath)
            with open(META_FILE, 'r+') as f:
                records = json.load(f)
                records = [r for r in records if r['name'] != filename]
                f.seek(0)
                json.dump(records, f, indent=4)
                f.truncate()
            update_dashboard()
            log_message(f"Deleted: {filename}")
        except Exception as e:
            log_message(f"Delete error: {e}")

def send_file(sock, filename, password, progress_callback):
    try:
        key = derive_key(password)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        filename_bytes = os.path.basename(filename).encode()
        sock.sendall(struct.pack('I', len(filename_bytes)) + filename_bytes)

        total_size = os.path.getsize(filename)
        sock.sendall(struct.pack('I', total_size + 32))

        sock.sendall(iv)

        with open(filename, 'rb') as f:
            sent_bytes = 0
            while chunk := f.read(65536):
                chunk = pad_data(chunk)
                encrypted_chunk = encryptor.update(chunk)
                sock.sendall(encrypted_chunk)
                sent_bytes += len(chunk)
                progress_callback(sent_bytes, total_size)
            sock.sendall(encryptor.finalize())
        
        log_message("File sent successfully")
    except Exception as e:
        log_message(f"Send error: {e}")

def receive_file(key, port, progress_callback):
    host = '0.0.0.0'
    try:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536 * 4)
        s.bind((host, port))
        s.listen(1)
        log_message("Receiver is listening...")
        client, addr = s.accept()
        log_message(f"Connection: {addr}")

        filename_len = struct.unpack('I', client.recv(4))[0]
        filename = client.recv(filename_len).decode()
        size = struct.unpack('I', client.recv(4))[0]

        iv = client.recv(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        data = b''
        received_bytes = 0
        while len(data) < size:
            chunk = client.recv(65536)
            data += decryptor.update(chunk)
            received_bytes += len(chunk)
            progress_callback(received_bytes, size)

        data += decryptor.finalize()
        decrypted = unpad_data(data)

        filepath = os.path.join(RECEIVED_DIR, filename)
        with open(filepath, 'wb') as f:
            f.write(decrypted)

        record = {"name": filename, "size": f"{len(decrypted)} bytes", "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        with open(META_FILE, 'r+') as f:
            records = json.load(f)
            records.append(record)
            f.seek(0)
            json.dump(records, f, indent=4)
            f.truncate()

        update_dashboard()
        log_message(f"Received: {filename}")
        client.close()
        s.close()
    except Exception as e:
        log_message(f"Receive error: {e}")

def progress_callback(sent_bytes, total_size):
    progress = (sent_bytes / total_size) * 100
    progress_bar['value'] = progress
    root.update_idletasks()

def send_file_gui():
    try:
        password, filename, host, port = password_entry.get(), file_path_label.cget("text"), host_entry.get(), int(port_entry.get())
        if password and filename and host and port:
            s = socket.socket()
            s.connect((host, port))
            threading.Thread(target=send_file, args=(s, filename, password, progress_callback), daemon=True).start()
        else:
            log_message("Missing fields")
    except Exception as e:
        log_message(f"Send GUI error: {e}")

def threaded_receive():
    try:
        key, port = password_entry.get(), int(port_entry.get())
        if key and port:
            threading.Thread(target=receive_file, args=(derive_key(key), port, progress_callback), daemon=True).start()
        else:
            log_message("Missing key or port")
    except Exception as e:
        log_message(f"Receive thread error: {e}")

def receive_file_gui():
    threading.Thread(target=threaded_receive, daemon=True).start()

def choose_file():
    filename = filedialog.askopenfilename()
    if filename:
        file_path_label.config(text=filename)

def update_mode():
    mode = mode_var.get()
    host_entry.configure(state='normal' if mode == 'send' else 'disabled')
    choose_file_button.configure(state='normal' if mode == 'send' else 'disabled')
    if mode == 'receive':
        file_path_label.config(text="Waiting for file...")
    else:
        file_path_label.config(text="Send File")

def get_wifi_ipv4():
    for interface, snics in psutil.net_if_addrs().items():
        if 'Wi-Fi' in interface or 'wlan' in interface.lower():
            for snic in snics:
                if snic.family == socket.AF_INET:
                    return snic.address
    return 'Not connected'

def update_ip_address():
    try:
        ip = get_wifi_ipv4()
        ip_label.config(text=f"IP: {ip}")
    except:
        ip_label.config(text="IP: N/A")
    root.after(5000, update_ip_address)

def setup_dark_theme():
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview",
                    background="#222222",
                    foreground="white",
                    fieldbackground="#222222",
                    rowheight=25,
                    font=('Century Schoolbook', 10))
    style.configure("Treeview.Heading",
                    background="#111111",
                    foreground="white",
                    font=('Century Schoolbook', 10, 'bold'))
    style.map("Treeview",
              background=[('selected', '#444444')],
              foreground=[('selected', 'white')])
    style.configure("TProgressbar",
                    thickness=30,  # Thickness of the progress bar
                    troughcolor="#333333",  # Color of the background
                    background="#4caf50",  # Color of the progress (Green)
                    )
    style.map("TProgressbar",
              background=[('active', '#76c7c0')])

root = tk.Tk()
root.title("AES-Based Cross-Platform Secure FIle Transfer")
root.geometry('700x800')
root.configure(bg='black')
setup_dark_theme()

def configure_widget(widget, font=('Century Schoolbook', 10, 'bold'), bg='black', fg='white'):
    widget.configure(bg=bg, fg=fg, font=font)
    if isinstance(widget, tk.Entry):
        widget.configure(insertbackground='white')


# UI Setup
widgets = []
for label in ["AES-Based Cross-Platform Secure File Transfer", "by uvbs"]:
    l = tk.Label(root, text=label, font=('Century Schoolbook', 16 if "Secure" in label else 10, 'bold' if "Secure" in label else 'italic'))
    configure_widget(l)
    l.pack(pady=5)

ip_label = tk.Label(root, text="Device IP: Detecting...", font=('Century Schoolbook', 10, 'bold'))
configure_widget(ip_label)
ip_label.pack(pady=2)
update_ip_address()

mode_var = tk.StringVar(value="send")
send_radio = tk.Radiobutton(root, text="Send", variable=mode_var, value="send", command=update_mode, selectcolor='black')
receive_radio = tk.Radiobutton(root, text="Receive", variable=mode_var, value="receive", command=update_mode, selectcolor='black')
for r in [send_radio, receive_radio]:
    configure_widget(r)
    r.pack(pady=2)

for label_text, entry in [("Enter Host:", 'host_entry'), ("Enter Port:", 'port_entry'), ("Enter Password/Key:", 'password_entry')] :
    l = tk.Label(root, text=label_text)
    configure_widget(l)
    l.pack()
    e = tk.Entry(root, show="*" if "Password" in label_text else None)
    configure_widget(e)
    e.pack(pady=2)
    globals()[entry] = e

file_path_label = tk.Label(root, text="No file chosen")
configure_widget(file_path_label)
file_path_label.pack(pady=2)

choose_file_button = tk.Button(root, text="Choose File", command=choose_file)
configure_widget(choose_file_button)
choose_file_button.pack(pady=2)

execute_button = tk.Button(root, text="Execute", command=lambda: send_file_gui() if mode_var.get() == "send" else receive_file_gui())
configure_widget(execute_button)
execute_button.pack(pady=5)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=600, mode="determinate", style="TProgressbar")
progress_bar.pack(pady=2)

status_label = tk.Label(root, text="")
configure_widget(status_label)
status_label.pack(pady=4)

log_label = tk.Label(root, text="Log Viewer:")
configure_widget(log_label)
log_label.pack(pady=2)

log_viewer = scrolledtext.ScrolledText(root, height=2, bg='black', fg='white', font=('Century Schoolbook', 10))
log_viewer.pack(fill=tk.BOTH, padx=10, pady=5)

search_frame = tk.Frame(root, bg='black')
search_frame.pack(pady=4, fill=tk.X, padx=5)

search_label = tk.Label(search_frame, text="Search")
configure_widget(search_label)
search_label.pack(side=tk.LEFT, padx=(0, 5))

search_var = tk.StringVar()
search_entry = tk.Entry(search_frame, textvariable=search_var)
configure_widget(search_entry)
search_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
search_entry.bind('<KeyRelease>', lambda e: update_dashboard())

refresh_button = tk.Button(search_frame, text="Refresh Dashboard", command=update_dashboard)
configure_widget(refresh_button)
refresh_button.pack(side=tk.RIGHT, padx=(5, 0))

dashboard = ttk.Treeview(root, columns=("Filename", "Size", "Timestamp"), show='headings', height=4)
dashboard.heading("Filename", text="Filename")
dashboard.heading("Size", text="Size")
dashboard.heading("Timestamp", text="Timestamp")
dashboard.pack(fill=tk.BOTH, padx=10, pady=5)

delete_button = tk.Button(root, text="Delete Selected", command=delete_selected)
configure_widget(delete_button)
delete_button.pack(pady=2)


update_mode()
update_dashboard()
root.mainloop()
