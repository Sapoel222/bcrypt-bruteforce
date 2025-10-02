
# 🔐 Bcrypt Bruteforce (Python + Multiprocessing)

A fast, simple **dictionary attacker for Bcrypt hashes** written in Python.  

---

## ✨ Features

- Supports standard Bcrypt hashes: `$2a$`, `$2b$`, `$2y$`
- **Multiprocessing**: splits the wordlist across workers (`-W`), by default uses **all detected cores**
- **Early stop**: once a worker finds the password, the rest are stopped
- **Progress bar with ETA** via `tqdm` (disable with `--no-progress`)
- Custom **encoding** for wordlists (UTF‑8 by default)

---

## 📦 Installation

```bash
git clone https://github.com/your-user/bcrypt-bruteforce.git
cd bcrypt-bruteforce
pip install -r requirements.txt
```

> Or install dependencies directly: `pip install bcrypt tqdm`

---

## ⚡ Quick Start

```bash
python3 bcrypt-bruteforce.py -H '$2b$10$YOUR_HASH_HERE......................' -w examples/wordlist_example.txt
```

### CLI Options

| Option | Description |
|-------|-------------|
| `-H, --hash` | Bcrypt hash to check (required) |
| `-w, --wordlist` | Path to the wordlist file (required) |
| `-e, --encoding` | Wordlist encoding (default: `utf-8`) |
| `-W, --workers` | **Number of processes** to use (default: **all detected cores**) |
| `--no-progress` | Disable the progress bar (useful for CI/logs) |

#### Examples

```bash
# Default: use all detected CPU cores
python3 bcrypt-bruteforce.py -H '$2b$10$...' -w rockyou.txt

# Force 4 processes
python3 bcrypt-bruteforce.py -H '$2b$12$...' -w passwords.txt -W 4

# Disable progress bar
python3 bcrypt-bruteforce.py -H '$2b$10$...' -w wordlist.txt --no-progress

# Use a different encoding
python3 bcrypt-bruteforce.py -H '$2b$10$...' -w wordlist.txt -e latin-1
```

---

## 🧠 How it Works

1. The script splits the wordlist file into `N` byte‑ranges based on `--workers` (by default, all detected cores).
2. Each worker reads **only its segment**, aligning to full lines, and attempts `bcrypt.checkpw()` per entry.
3. When any worker finds the correct password, it **signals** the others to stop and prints the match.
4. A shared counter feeds the **global progress bar** and **ETA** (if enabled).

---

## 🏎️ Performance Tips

- Bcrypt is CPU‑bound. Higher **cost/work factor** → fewer attempts per second (for both correct and incorrect guesses).
- Use an **SSD** for large wordlists.
- Try different `-W` values; sometimes `cores - 1` yields better overall system responsiveness.
- Decompress compressed lists first (`.gz`, `.zip`): byte‑range splitting requires plain text files.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing, research, and learning** only.  
Do **not** use it to access systems without explicit permission.
