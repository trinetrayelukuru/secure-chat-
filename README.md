# SecureChat — Encrypted Multi-Client Chat

A small, beginner-friendly chat application written in Python. One computer runs a
**server**, and several other computers (or several terminal windows on the same
computer) run **clients**. Every message is encrypted with a **shared Fernet key**
before it is sent over TCP, and the server broadcasts each message to everyone who
is connected.

> **Status:** working student / learning project. It demonstrates sockets,
> threading, JSON framing and symmetric encryption. It is **not** a
> production-hardened secure messenger — see
> [Security limitations](#13-security-limitations).

---

## Table of contents

1. [Project overview](#1-project-overview)
2. [Features](#2-features)
3. [Architecture](#3-architecture)
4. [Prerequisites](#4-prerequisites)
5. [Installation from scratch on Windows 11](#5-installation-from-scratch-on-windows-11)
6. [Environment configuration](#6-environment-configuration)
7. [Running SecureChat locally](#7-running-securechat-locally)
8. [Running multiple clients](#8-running-multiple-clients)
9. [Connecting multiple laptops](#9-connecting-multiple-laptops)
10. [How SecureChat works internally](#10-how-securechat-works-internally)
11. [Dependencies](#11-dependencies)
12. [Testing](#12-testing)
13. [Security limitations](#13-security-limitations)
14. [Troubleshooting](#14-troubleshooting)
15. [Project status and future improvements](#15-project-status-and-future-improvements)
16. [License, contributing, and repository usage](#16-license-contributing-and-repository-usage)

---

## 1. Project overview

### What it is

SecureChat is a terminal chat program:

- `server.py` listens on TCP port **5555** and keeps a table of
  `username -> socket`.
- `client.py` connects to that server, asks for a username, and then lets you type
  chat messages.
- Every message (login, chat, command, server reply) is JSON, encrypted with
  **Fernet**, and terminated by a newline so the receiver knows where one message
  ends and the next begins.

### What problem it solves

It is a compact, readable example of the classic Computer Networks project:
**multiple clients, one server, application-layer encryption, and safe
multi-threaded handling of shared state** — without a web framework, a database,
or a cloud service.

### Implemented today

- Multi-client TCP chat with broadcast
- Username login with duplicate-name rejection
- Fernet encryption of every frame in both directions
- Newline-delimited message framing with a per-connection receive buffer
- `/users` and `/quit` commands
- Colourised terminal UI with a shared banner for server and client
- A regression suite (`test_securechat.py`) that starts a real server and real
  clients

### Not implemented (future work)

TLS, per-user keys, password accounts, message history, file transfer, a GUI, and
internet-grade deployment. These are listed again in
[section 15](#15-project-status-and-future-improvements).

---

## 2. Features

| Feature | How it behaves |
|---|---|
| Multi-client TCP chat | The server accepts many connections and broadcasts each chat line to all logged-in clients (including the sender). |
| Usernames | After connecting, the client prints `username >> ` and asks for a name. Empty names are re-prompted. |
| Duplicate usernames | The server refuses the second connection with `Username '<name>' is already taken...` and closes it. |
| Encryption | `protocol.py` encrypts every JSON payload with Fernet (AES-128-CBC + HMAC-SHA256, as provided by `cryptography`). |
| Message framing | Each encrypted token is followed by `\n`. Receivers buffer bytes and split on the newline, so partial `recv()` reads never corrupt a message. |
| `/users` | Asks the server for the online-user list; every client sees `=== Online users (n): ... ===`. |
| `/quit` | Tells the server you are leaving; the client exits and the server broadcasts `<name> left the chat.` |
| Unknown commands | `/anything-else` is answered with an error listing the supported commands — it is never broadcast as chat. |
| Terminal UI | `ui.py` draws the shared banner (auto-sized to the terminal), colourised events, timestamps and per-user colours. Falls back to plain text when colour is unavailable. |
| Graceful cleanup | Disconnects, send failures and even a client that stops reading are cleaned up once, under a lock, without leaking sessions. |
| Tests | 45 automated checks across protocol, server behaviour, end-to-end client runs and thread safety. |

Commands are deliberately simple: **`/users`** and **`/quit`** only.

---

## 3. Architecture

### Files

| File | Role |
|---|---|
| `server.py` | Entry point for the server. Binds `0.0.0.0:5555`, accepts connections, performs the username handshake, stores sessions in a `dict` guarded by a `threading.Lock`, handles commands, broadcasts messages, and cleans up on disconnect. |
| `client.py` | Entry point for the client. Connects to the server, prompts for a username, then runs one thread for keyboard input and one for incoming messages. Optional first argument = server IP/hostname. |
| `protocol.py` | The wire format. Loads `SECURECHAT_KEY` from `.env`, creates a `Fernet` cipher, and provides `encrypt_message()`, `decrypt_message()` and `receive_message()` (framing). |
| `ui.py` | Presentation only — no sockets or encryption. Banner, panels, event lines, chat lines, prompts, ANSI colour detection (including Windows virtual-terminal enabling). |
| `test_securechat.py` | Self-contained regression suite. Starts the real server on port 5555, drives the real protocol, launches real `client.py` subprocesses, and reports PASS/FAIL with exit code 0 or 1. |
| `requirements.txt` | The two third-party packages: `cryptography`, `python-dotenv`. |
| `.env.example` | Template for the local `.env` file (variable **name** and a placeholder, never a real key). |
| `.env` | **Your local secret** — holds the real `SECURECHAT_KEY`. Git-ignored, never published. |
| `.gitignore` | Keeps `.env`, `.venv/`, caches, logs and editor files out of Git. |
| `LICENSE` | MIT license. |

### Diagram

```text
        laptop / terminal 1                 laptop / terminal 2
        ┌─────────────────┐                 ┌─────────────────┐
        │  client.py      │                 │  client.py      │
        │  input thread   │                 │  input thread   │
        │  recv thread    │                 │  recv thread    │
        └────────┬────────┘                 └────────┬────────┘
                 │  TCP :5555                         │
                 │  Fernet ciphertext + "\n"           │
                 ▼                                    ▼
        ┌──────────────────────────────────────────────────────┐
        │                     server.py                        │
        │  accept loop  ──►  one thread per connection         │
        │  clients = { "alice": socket, "bob": socket, ... }   │
        │  client_lock guards the dict (never held during I/O) │
        │  chat  ──► broadcast to every connected client       │
        │  /users ──► reply only to the asking client          │
        └──────────────────────────────────────────────────────┘
                 │                                    │
                 ▼                                    ▼
        laptop / terminal 3                 laptop / terminal 4
        ┌─────────────────┐                 ┌─────────────────┐
        │  client.py      │                 │  client.py      │
        └─────────────────┘                 └─────────────────┘
```

Important: the encryption happens in the **client and server processes**. TCP
itself is plain TCP — there is no TLS layer underneath.

---

## 4. Prerequisites

| Requirement | Why |
|---|---|
| **Python 3.9 or newer** (tested on Python **3.13.0**) | The code uses modern type hints such as `dict[str, socket.socket]`. |
| **Git** | To clone the repository and to push changes. |
| **VS Code** (optional) | A convenient editor with an integrated PowerShell terminal. |
| **PowerShell** (or Windows Terminal / Command Prompt) | To run the server and clients. |
| **Two or more devices on the same Wi-Fi / LAN** | Only needed for the multi-laptop test. One laptop is enough for local testing. |

**Python vs Python packages.** Python itself is the interpreter you install once
(`python.exe`). Packages such as `cryptography` are extra libraries stored inside a
*project* folder (`.venv/`), not inside Python. That is why this project has a
`requirements.txt`: it is the list of packages to install **into this project's
virtual environment**.

Check your versions:

```powershell
py --version
git --version
```

Expected (yours may be newer):

```text
Python 3.13.0
git version 2.48.1.windows.1
```

---

## 5. Installation from scratch on Windows 11

Open **PowerShell** (Win + X → *Terminal*) and run the steps in this order.

### Step 1 — Get the code

```powershell
git clone https://github.com/trinetrayelukuru/secure-chat-.git
```

Downloads the repository into a folder named `secure-chat-`. *Why:* you need the
project files on your machine, and `git clone` also wires up `origin` so you can
push later.

```powershell
cd secure-chat-
```

Moves your shell into the project folder. Every later command assumes you are here.

> Note: the default GitHub branch of this repository is `main`.

### Step 2 — Create a virtual environment

```powershell
py -m venv .venv
```

Creates an isolated Python environment inside `.venv\`. *Why:* the two packages are
installed only for this project, so they cannot break other Python projects on the
same laptop. Nothing is installed globally.

### Step 3 — Activate it

```powershell
.\.venv\Scripts\Activate.ps1
```

Puts `.venv\Scripts` first on your `PATH`, so `python` and `pip` now mean this
project's environment. Your prompt shows `(.venv)` when it worked.

**If PowerShell blocks the script** (`... cannot be loaded because running scripts
is disabled on this system`), you have two safe options — do **not** change the
machine-wide execution policy just for this project:

**Option A — activate only for the current window:**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

**Option B — skip activation entirely** and call the interpreter by path:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe server.py
```

Both options behave the same; the venv does not have to be "activated" for its
`python.exe` to work. All commands in this README are shown with the explicit
`.\.venv\Scripts\python.exe` path for that reason.

### Step 4 — Upgrade pip (recommended)

```powershell
python -m pip install --upgrade pip
```

`pip` is Python's package installer. This updates it inside the venv so it can read
modern package metadata and use current download behaviour.

### Step 5 — Install the project packages

```powershell
pip install -r requirements.txt
```

Reads `requirements.txt` and installs each listed package plus its own
dependencies. Expected output ends with something like:

```text
Successfully installed cryptography-<version> python-dotenv-<version> cffi-<version> pycparser-<version>
```

### Step 6 — Create your local `.env`

```powershell
Copy-Item .env.example .env
```

Copies the template to the real configuration file. `.env` is git-ignored.

### Step 7 — Generate the shared key and paste it into `.env`

```powershell
.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Prints a random 44-character key, for example a string that looks like
`<44 random URL-safe characters>`. Open `.env` in VS Code and replace the
placeholder after `SECURECHAT_KEY=` with that value. See
[section 6](#6-environment-configuration) for how to share it with other laptops.

### One-block summary

```powershell
git clone https://github.com/trinetrayelukuru/secure-chat-.git
cd secure-chat-
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# paste the printed key into .env after SECURECHAT_KEY=
```

---

## 6. Environment configuration

`protocol.py` executes this at import time:

```python
load_dotenv()
KEY = os.environ["SECURECHAT_KEY"]
cipher = Fernet(KEY)
```

So **both the server and every client need a `.env` file with a valid
`SECURECHAT_KEY`**, and they must all use the *same* key.

| Variable | Required | Meaning |
|---|---|---|
| `SECURECHAT_KEY` | **Yes** | The shared Fernet key used to encrypt and decrypt every message. |
| `SECURECHAT_COLOR` | No | `always` or `never` to force/disarm ANSI colour in `ui.py`. |
| `NO_COLOR` | No | If set (any value), colour is disabled. |

### Create `.env`

```powershell
Copy-Item .env.example .env
notepad .env
```

### Generate a key

```powershell
.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Each participant must use the **same** key value. Share it privately (in person,
or through a password manager / end-to-end encrypted message). Never put it in
GitHub, a screenshot, a group chat, or `.env.example`.

### Why `.env` is not in Git

Anyone with the key can decrypt captured traffic. `.gitignore` excludes `.env`
and `.env.*` while keeping `.env.example` (`!.env.example`). If a real key were
ever committed, deleting the file would **not** remove it from Git history —
the key would have to be considered compromised and regenerated.

> **Note:** Changing the key is a coordinated action. All clients and the server
> must switch together, otherwise the server replies with
> `Invalid or corrupted message` (or `Invalid username message` during login).

---

## 7. Running SecureChat locally

You need **two terminal windows**: one for the server, one for a client.

### Terminal 1 — server

```powershell
cd "D:\computer networks\SECURE CHAT"
.\.venv\Scripts\python.exe server.py
```

(With the venv activated, `python server.py` is equivalent.)

Expected output: the SecureChat banner, a `SERVER` panel showing
`STATUS RUNNING`, `LISTEN 0.0.0.0:5555`, then:

```text
[HH:MM:SS] READY server ready - waiting for clients
```

Leave this window open. `Ctrl+C` stops the server.

### Terminal 2 — client

```powershell
cd "D:\computer networks\SECURE CHAT"
.\.venv\Scripts\python.exe client.py
```

Expected output: the banner, a `COMMANDS` panel, a `CONNECTION` panel, then:

```text
[HH:MM:SS] READY connected to 127.0.0.1:5555
  username >>
```

Type a name (for example `alice`) and press Enter. The server replies:
`Welcome alice! Use /users to see online users.` and every client sees
`alice joined the chat.`

Then type a message and press Enter — all other clients receive it as
`[alice]: your message`, and your own window shows it too.

### Commands

| Input | Result |
|---|---|
| `hello` | Broadcast to every connected client. |
| `/users` | Replies only to you: `=== Online users (n): alice, bob ===` |
| `/quit` | Disconnects you; other clients see `alice left the chat.` |
| `/typo` | Error from the server listing the supported commands; nothing is broadcast. |
| `Ctrl+C` | Sends `/quit`, then exits the client. |

Client exit is connection-driven: when the server closes the socket, the client
prints `connection closed by the server` and terminates.

---

## 8. Running multiple clients

On one laptop, open additional PowerShell windows and start more clients:

```powershell
.\.venv\Scripts\python.exe client.py
```

- Use a **different username** in each window (`alice`, `bob`, `carol`).
- Reusing a name is rejected: the second connection prints
  `Username 'alice' is already taken...` and the client exits.
- Type in one window and watch the others — the message appears everywhere,
  prefixed with the sender's name.
- Run `/users` in any window to see the live list.
- `/quit` (or closing the window) removes that user from `/users`.

Stop everything cleanly by running `/quit` in each client, then `Ctrl+C` in the
server window. After shutdown, nothing should be listening on port 5555:

```powershell
Get-NetTCPConnection -LocalPort 5555 -State Listen -ErrorAction SilentlyContinue
```

No output means the port is free.

---

## 9. Connecting multiple laptops

All devices should be on the **same trusted Wi-Fi / LAN**.

1. Start the server on the "server laptop" (Terminal 1 command above). It binds
   `0.0.0.0`, which means "all network interfaces", so other machines can reach it.
2. Find that laptop's private IPv4 address:

   ```powershell
   ipconfig
   ```

   Look for the active Wi-Fi/Ethernet adapter and note `IPv4 Address`,
   e.g. `192.168.1.42`.
3. On the other laptops, pass that IP as the **first argument**:

   ```powershell
   .\.venv\Scripts\python.exe client.py 192.168.1.42
   ```

   The client prints `connected to 192.168.1.42:5555`. The port is fixed at 5555
   and is not a command-line option.

### `127.0.0.1` vs the LAN address

- `127.0.0.1` / `localhost` = *this* computer only. Use it for same-machine tests.
- The server's `192.168.x.x` address = reachable from other devices on the LAN.
- The server's `0.0.0.0` is a **bind** address, not an address clients can connect
  to. Never type `0.0.0.0` into the client.

### Firewall

Windows may prompt the first time Python listens; allow it on **Private networks**.
If other laptops get `Connection refused` / timeout, allow inbound TCP 5555
(private profile only):

```powershell
# Run PowerShell as Administrator. Private profile only.
New-NetFirewallRule -DisplayName "SecureChat 5555" -Direction Inbound -Protocol TCP -LocalPort 5555 -Action Allow -Profile Private
```

Also confirm both laptops are on the same subnet and that the Wi-Fi network does
not use "client isolation" (common on guest networks) — that blocks device-to-device
traffic entirely.

> **Do not expose port 5555 to the public internet.** There is no TLS and one
> shared key for everybody; this prototype is for a trusted LAN only.

---

## 10. How SecureChat works internally

1. **Connect.** `client.py` creates a TCP socket and connects to the server's
   IP on port 5555.
2. **Handshake.** The server sends an encrypted `auth_request`. The client asks
   you for a username, then sends an encrypted `{"type": "auth", "username": ...}`.
3. **Validation.** The server checks the username is non-empty and not already in
   `clients`. Duplicates get an error and are disconnected; a new name is stored in
   the session table and announced to everyone.
4. **Encoding.** A message is built as a Python `dict`, serialised with
   `json.dumps()`, UTF-8 encoded, then encrypted with Fernet.
5. **Framing.** The ciphertext is followed by a single `\n`.
6. **Sending.** `sendall()` writes the whole frame. The receiver accumulates bytes
   in a buffer, and `receive_message()` splits out complete frames whenever a
   newline arrives, keeping the remainder for the next `recv()`.
7. **Decryption.** The receiver calls `cipher.decrypt()` and `json.loads()`. A bad
   token produces a friendly error instead of crashing the process.
8. **Routing.** Chat frames are broadcast to every connected client; `/users`
   replies only to the asker; `/quit` ends the session.
9. **Cleanup.** When `recv()` returns empty or fails, the server removes the
   session (verifying it still owns that socket), closes it, and broadcasts
   `<name> left the chat.`

### Beginner glossary

- **TCP** — a reliable, ordered byte stream between two programs. It guarantees
  delivery and ordering but says nothing about message boundaries.
- **Message framing** — a convention for where a message ends. Here: a newline.
  Without it, two messages arriving in one `recv()` would be indistinguishable.
- **JSON** — text format for structured data (`{"type": "chat", ...}`). Easy to
  read, but it is *plain text* until encrypted.
- **Fernet** — a recipe from the `cryptography` package: AES-128-CBC encryption
  plus HMAC-SHA256 authentication, with a timestamp. It detects tampering: a
  modified token raises `InvalidToken`.
- **Symmetric / shared key** — the same key encrypts and decrypts, so everyone
  must hold it. Convenient, but it means there is no per-user secrecy.
- **Thread** — an independent flow of execution. Each connection has its own
  thread, so a slow or idle client cannot freeze the server.
- **`threading.Lock`** — a mutex that keeps the shared `clients` dictionary
  consistent. The server deliberately releases it before any network send so one
  stalled client cannot block everyone else.
- **Virtual environment** — a private package folder per project.
- **`.env` + `python-dotenv`** — configuration kept outside the code, so secrets
  are not hard-coded or committed.

### Wire format, concretely

```text
 chat message  ──json──►  {"type":"chat","message":"hi"}
               ─fernet─►  gAAAAAB...==\n
 server        ─fernet─►  {"type":"chat","username":"alice","message":"hi"}\n
```

There is **no TLS**: the TCP connection itself is unencrypted; only these payloads
are encrypted.

---

## 11. Dependencies

`requirements.txt` lists exactly two third-party packages:

```text
cryptography
python-dotenv
```

| Package | Installed separately? | Used for |
|---|---|---|
| `cryptography` | Yes (`pip`) | Provides `cryptography.fernet.Fernet` — encryption, decryption and tamper detection in `protocol.py`. It pulls in `cffi` and `pycparser`. |
| `python-dotenv` | Yes (`pip`) | `load_dotenv()` reads `.env` into environment variables at import time. |

Everything else is part of Python's standard library, so it needs no install:
`socket`, `threading`, `json`, `os`, `sys`, `ctypes`, `shutil`, `datetime`,
`subprocess`, `struct`, `time`.

Install and verify:

```powershell
pip install -r requirements.txt
python -c "import cryptography, dotenv; print('cryptography', cryptography.__version__); print('python-dotenv ok')"
```

Expected shape:

```text
cryptography 50.0.2
python-dotenv ok
```

Or list everything installed in the venv:

```powershell
pip list
```

No other packages are needed. `requirements.txt` intentionally does not pin exact
versions, so a fresh install picks current releases (verified working with
`cryptography 50.0.2` and `python-dotenv 1.2.4` on Python 3.13.0).

---

## 12. Testing

```powershell
.\.venv\Scripts\python.exe test_securechat.py
```

The suite starts its own server on port **5555**, so stop any running
`server.py` first. It writes `server_test.log` in the project root (git-ignored)
and prints one line per check.

### What it verifies

| Phase | Coverage |
|---|---|
| 0 — idle pre-auth | A client that connects and never sends a username does not block other logins. |
| 1 — raw protocol / server behaviour | Welcome message, auth rejection, duplicate usernames, encrypted frames, `/users` accuracy, `/quit`, leave notice, unknown-command errors, corrupted-payload handling, broadcast delivery and exemption of the sender from duplicate notices. |
| 2 — end-to-end with `client.py` | Real client subprocesses log in, see join notices, exchange chat, use `/users`, handle invalid commands, and exit on `/quit`; duplicate clients are rejected and exit. |
| 3 — wedged client / thread safety | `/users` still answers while a client is not reading, and the stalled client is reaped exactly once when its socket fails. |

### Current result (verified on 2026-10-19)

```text
45/45 checks passed
```

Exit code **0** means every check passed; exit code **1** means at least one
failed (the script then prints the failures and the tail of the server log).
No extra dependencies are required.

**Limitations:** the suite runs against the fixed port 5555, so it cannot run in
parallel with itself or with a live server; it is an integration script, not a
`pytest` suite, and it does not test TLS or internet deployment (neither exists).

---

## 13. Security limitations

Read this before treating the project as "secure":

- **Shared key.** One Fernet key encrypts everything for everybody. Every
  participant can decrypt every message, including the server's traffic — and
  anyone who obtains the key can decrypt captured messages.
- **No TLS.** The TCP connection itself is not encrypted or authenticated. On an
  untrusted network, an active attacker could intercept the connection or
  impersonate the server; nothing pins or verifies the server's identity.
- **Usernames are not authentication.** A name is only "first come, first served".
  There are no passwords, accounts or identities, so nothing prevents someone from
  taking a free name or claiming to be someone else next time.
- **No per-user keys** and no forward secrecy: one key, valid indefinitely.
- **Replay is not defended at the application layer.** Fernet tokens carry a
  timestamp, but `protocol.py` decrypts without a TTL, so old tokens are not
  rejected for age, and there is no nonce/sequence tracking. A captured token
  replayed into a connection would be decrypted.
- **No rate limiting, no message size limit, no audit log.** A client can flood.
- **LAN prototype only** — not hardened, and not independently security-audited.

The value of this project is that it shows *where* those protections go, not that
it implements all of them.

---

## 14. Troubleshooting

**`python` or `py` is not recognized**
Install Python from python.org and tick *Add python.exe to PATH*, then reopen the
terminal. Check with `py --version`. As a fallback use the full path
`.\.venv\Scripts\python.exe`.

**Virtual environment not found (`The system cannot find the path specified`)**
You are probably not in the project folder, or `.venv` was never created. Run
`cd` into the folder containing `server.py`, then `py -m venv .venv`.

**PowerShell blocks activation**
Use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` for that window
only, or skip activation and call `.\.venv\Scripts\python.exe` directly. Do not
change the machine-wide policy just for this.

**`ModuleNotFoundError: No module named 'cryptography'` (or `dotenv`)**
You are running a different Python than the one you installed into. Reinstall with
`.\.venv\Scripts\python.exe -m pip install -r requirements.txt` and run with the
same `.\.venv\Scripts\python.exe`.

**`KeyError: 'SECURECHAT_KEY'`**
There is no `.env` in the working directory, or the variable name is misspelled.
`Copy-Item .env.example .env`, then put a real generated key after
`SECURECHAT_KEY=`. The server and client must be started from the project folder.

**`ValueError: Fernet key must be 32 url-safe base64-encoded bytes`**
The value in `.env` is not a generated key (e.g. the placeholder is still there).
Generate a key with the command in [section 6](#6-environment-configuration).

**`ConnectionRefusedError` / client prints `CONNECTION FAILED`**
The server is not running, or you used the wrong host/port. Start `server.py`
first. For another laptop, use the server's LAN IP (not `127.0.0.1`), and check
the firewall rule.

**`OSError: [WinError 10048] ... only one usage of each socket address` / port 5555 in use**
Another server or the test suite is still running. Find and close it:

```powershell
Get-NetTCPConnection -LocalPort 5555 -State Listen | Select-Object OwningProcess
Get-Process -Id <PID>
```

Then stop that process (or press `Ctrl+C` in its window). `TIME_WAIT` entries seen
in `netstat` after a test are normal and disappear by themselves.

**`Username 'alice' is already taken`**
Pick a different name; names must be unique among *currently connected* clients.
Closing a client frees its name immediately.

**`Invalid or corrupted message` / `Invalid username message`**
The two sides are using different keys, or a frame got mangled. Compare
`SECURECHAT_KEY` on every machine and restart both sides after changing `.env`.

**`fatal: not a git repository`**
`git init`, then add the remote:
`git remote add origin https://github.com/trinetrayelukuru/secure-chat-.git`.

**GitHub authentication fails on push**
Sign in through the Git Credential Manager window when it appears, or use a
Personal Access Token as the password (classic tokens need the `repo` scope).
Verify the remote with `git remote -v`.

**Push rejected because the remote has commits (`fetch first`)**
Do **not** force-push. Integrate instead:

```powershell
git pull --rebase origin main
git push -u origin main
```

**Banner looks broken, wraps, or shows `[91m`-style codes**
The banner is ~149 columns wide and shrinks automatically: stacked logo → compact
header. Widen the window, or use Windows Terminal. If escape codes appear literally,
colour detection failed: set `SECURECHAT_COLOR=never` for plain text, or
`SECURECHAT_COLOR=always` to force it. `NO_COLOR=1` disables colour too.

**Typing gets mixed with incoming messages**
The UI writes each line atomically above the prompt. If you use a very old console
without ANSI support, run with `SECURECHAT_COLOR=never`; the client still redraws
the `>>` prompt after each incoming line.

---

## 15. Project status and future improvements

**Working now:** server/client chat, unique usernames, Fernet-encrypted JSON frames,
newline framing, broadcast, `/users`, `/quit`, unknown-command errors, graceful
disconnect cleanup, shared banner UI, and a 45-check regression suite.

**Future work (not implemented):**

- TLS (e.g. `ssl` with a self-signed certificate) to protect the transport and
  authenticate the server.
- Per-user key pairs (asymmetric), so the shared-key model is no longer required.
- Password accounts or another real identity mechanism.
- Message authentication with replay protection (sequence numbers / nonces, TTL
  checks), and rate limiting.
- A `pytest`-based unit suite with a configurable free port for CI.
- A configurable port/host (e.g. environment variables) and systemd/Windows
  service packaging.
- Optional GUI or web client.

---

## 16. License, contributing, and repository usage

### License

Released under the **MIT License** — see [LICENSE](LICENSE).
Copyright (c) 2026 Trinetra Yelukuru.

### Contributing

1. Fork the repository (or, if you have write access, branch from `main`).
2. Create a branch: `git checkout -b feature/my-change`.
3. Keep changes small and preserve the existing protocol on port 5555.
4. Run the checks before committing:
   ```powershell
   .\.venv\Scripts\python.exe -m py_compile server.py client.py protocol.py ui.py
   .\.venv\Scripts\python.exe test_securechat.py
   ```
5. Never commit `.env`, `.venv/`, logs, or any real key.
6. Open a pull request describing *why* the change is needed.

### Repository usage

```powershell
git clone https://github.com/trinetrayelukuru/secure-chat-.git
cd secure-chat-
```

The default branch is `main`. If you only want to run the app, follow
[section 5](#5-installation-from-scratch-on-windows-11). If you want to publish your
own copy, change the remote:

```powershell
git remote set-url origin https://github.com/<your-username>/<your-repo>.git
```

> **Reminder:** this repository contains **no** encryption key. Every user
> generates (or is privately given) their own shared `SECURECHAT_KEY` in a local
> `.env`, and everyone who needs to chat together must use the same value.
