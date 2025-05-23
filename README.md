# AES-Based-Cross-Platform-File-Sharing-Tool
A cross-platform secure file sharing application using Python, enabling encrypted file transfers with **AES-256** in **CBC mode** with **PKCS7 padding.**

---

## Features

- **AES-256 Encryption** (CBC mode, PKCS7 Padding)
- **Password-based Key Derivation (PBKDF2 with SHA-256)**
- Compression with zlib for efficient transmission
- Cross-platform GUI using Tkinter
- Real-time transfer progress bar
- Error checks for missing inputs or password mismatch
- File sharing over TCP sockets

---

## Screenshot

![screenshot](./assets/"Main%20UI%20secure%20tool.png")

---

### 1. Clone the repository

```bash
git clone https://github.com/uvbs17/AES-Based-Cross-Platform-File-Sharing-Tool.git
cd AES-Based-Cross-Platform-File-Sharing-Tool
```

### 2. Requirements

```bash
pip install -r requirements.txt
```

### 3. Run

```bash
python "AES-Based Cross-Platform File Sharing Tool finaluv.py"
```

Make sure both sender and receiver run the app and both users must input the same password and port

### Contribution
Feel free to fork, raise issues or pull requests.
