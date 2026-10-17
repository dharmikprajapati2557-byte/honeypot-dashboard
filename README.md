# 🛡️ HoneyNet — Multi-Protocol Honeypot with Sci-Fi Web Dashboard

A Python-based honeypot that emulates **HTTP, FTP, SSH, Telnet, SMB, and SNMP**
services, logs every connection/command/credential attempt to SQLite, and is
controlled through a dark, neon-themed web dashboard with live feeds, alerts,
and per-protocol start/stop + banner switching.

![platform](https://img.shields.io/badge/platform-Windows-blue)
![python](https://img.shields.io/badge/python-3.10%2B-green)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## ✨ Features

- Real listening sockets for **HTTP, FTP, SSH, Telnet, SMB, SNMP** — correctly
  fingerprinted by `nmap -sV`
- Predefined "vulnerable-looking" banners per protocol (e.g. vsftpd 2.3.4,
  OpenSSH 5.3, Apache 2.2.8), swappable live from the dashboard
- Live event feed + captured credentials feed, auto-refreshing
- Start/stop each protocol independently from the web GUI
- First-run setup screen to create the dashboard's admin username/password
  (hashed, never stored in plain text)
- One-click JSON export of all logs
- Sci-fi / HUD-styled responsive dashboard (dark background, neon glow,
  animated scan lines)

---

## 📋 Requirements

| Requirement | Why |
|---|---|
| **Windows 10/11** | Target OS for this build |
| **Python 3.10+** | Runtime |
| **pip** | Comes with Python |
| **Git** | Only needed if you're cloning/pushing to GitHub |
| **Administrator rights** | Only if you switch to real ports (21, 22, 23, 80, 161, 445) |

### Downloads you need

1. **Python** → https://www.python.org/downloads/windows/
   During install, **check "Add Python to PATH"** — this is the #1 thing people forget.
2. **Git** (optional, for GitHub) → https://git-scm.com/download/win
3. This project's files (clone from GitHub, or unzip if you downloaded it directly)

---

## ⚙️ Step-by-Step Installation

```powershell
# 1. Open PowerShell and go to the project folder
cd path\to\honeypot

# 2. Create a virtual environment (keeps dependencies isolated)
python -m venv venv

# 3. Activate it
venv\Scripts\activate
# your prompt should now start with (venv)

# 4. Install dependencies
pip install -r requirements.txt
```

**What each step does:**
- `python -m venv venv` creates an isolated Python environment in a `venv/` folder so this project's packages don't clash with anything else on your system.
- `venv\Scripts\activate` switches your terminal into that environment.
- `pip install -r requirements.txt` installs Flask, Werkzeug, and (optionally) Paramiko for full SSH interaction.

---

## ▶️ Running the Dashboard

```powershell
cd web
python app.py
```

Then open **http://localhost:5000** in your browser.

- First visit → redirected to `/setup` → choose your dashboard **username** and **password** (min. 6 characters). This is created fresh by you, not predefined.
- After that → log in at `/login` with those credentials every time.

---

## 🎛️ Using the Dashboard

| Section | What it does |
|---|---|
| **Protocol Control** | Start/stop each honeypot service, pick its active banner |
| **Live Event Feed** | Every connect/command/disconnect, filterable by protocol |
| **Captured Credentials** | Usernames/passwords/community strings attackers submit |
| **Export (⇩ icon)** | Downloads all logs as JSON |

---

## 🔌 Default Ports

Binding to ports under 1024 requires admin rights on Windows and often
clashes with Windows' own services, so defaults use high ports instead:

| Protocol | Default port | Real port |
|---|---|---|
| HTTP | 8080 | 80 |
| FTP | 2121 | 21 |
| SSH | 2222 | 22 |
| Telnet | 2323 | 23 |
| SMB | 4450 | 445 |
| SNMP | 1610/udp | 161/udp |

To expose the real ports (so a remote `nmap` scan shows `21/tcp open ftp`,
etc.): run `python app.py` as **Administrator**, edit `core/config.py` →
`DEFAULT_PORTS`, and open the port in Windows Firewall, e.g.:
```powershell
New-NetFirewallRule -DisplayName "Honeypot FTP" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Allow
```

---

## 🧯 Troubleshooting — Common Errors

| Error | Cause | Fix |
|---|---|---|
| `'python' is not recognized...` | Python wasn't added to PATH during install | Reinstall Python and check "Add Python to PATH", or run `py` instead of `python` |
| `ModuleNotFoundError: No module named 'flask'` | Dependencies installed outside the venv, or venv not activated | Run `venv\Scripts\activate` first, then `pip install -r requirements.txt` again |
| `OSError: [WinError 10048] ... address already in use` | Another process is already using that port | Check with `netstat -ano \| findstr :2121`, kill that process or change the port in `core/config.py` |
| `PermissionError` when binding to a port | Trying to use a port under 1024 without admin rights | Run PowerShell "as Administrator", or keep using the default high ports |
| Browser shows "This site can't be reached" | App isn't running, or you're using the wrong port | Confirm `python app.py` is still running and shows `Running on http://127.0.0.1:5000` |
| Stuck on `/setup` every time you restart | `logs/state.json` was deleted or never saved | Make sure the `logs/` folder exists and is writable; re-enter credentials |
| SSH honeypot shows banner only, no fake login | `paramiko` isn't installed | `pip install paramiko` inside the venv, then restart the app |
| `git push` fails with `Support for password authentication was removed` | Using your GitHub password instead of a token | Generate a Personal Access Token (Settings → Developer settings) and use that as the password |

---

## ⚠️ Scope & Limitations

- SMB and SNMP are intentionally shallow — they register correctly as open
  services and capture the credential/community string, but don't implement
  the full protocol stack. For deep SMB/SNMP emulation, pair this with
  established tools like Cowrie or Conpot.
- **Never expose this on your real/production network** without network
  isolation (a separate VLAN or DMZ) — a honeypot's entire purpose is to
  attract attackers, so keep it away from anything sensitive.
- Only deploy on networks/systems you own or are explicitly authorized to
  monitor.

---

## 📄 License

MIT — see `LICENSE` file. Free to use, modify, and distribute with
attribution.

---

## 🙋 Support

If you hit an error not listed above, check the terminal output where
`python app.py` is running — it usually prints the Python traceback that
pinpoints the exact line and cause.
