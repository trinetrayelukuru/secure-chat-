"""Repeatable integration tests for SecureChat.

Run from the project root with the project venv:

    .venv/Scripts/python.exe test_securechat.py

The script starts its own server on the app's fixed TCP port 5555 (one server
per phase), drives the real JSON/Fernet protocol directly and also launches
real ``client.py`` subprocesses for an end-to-end check, then stops the server.

Exit code 0 means every check passed; 1 means at least one check failed.
No new dependencies are required.
"""

import os
import socket
import struct
import subprocess
import sys
import threading
import time

from protocol import encrypt_message, decrypt_message, receive_message

HOST = "127.0.0.1"
PORT = 5555
ROOT = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable
SERVER_LOG = os.path.join(ROOT, "server_test.log")

CHECKS = 0
FAILURES = []


def check(name, condition, detail=""):
    global CHECKS
    CHECKS += 1
    if condition:
        print(f"PASS  {name}")
    else:
        FAILURES.append(name)
        suffix = f"  -> {detail}" if detail else ""
        print(f"FAIL  {name}{suffix}")


def wait_until(predicate, timeout, interval=0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


# --------------------------------------------------------------------------- #
# Raw protocol client
# --------------------------------------------------------------------------- #
class RawClient:
    """Sends framed Fernet messages and records every decrypted reply."""

    def __init__(self, username, wait_welcome=True, timeout=5.0):
        self.username = username
        self.sock = socket.create_connection((HOST, PORT), timeout=5)
        self.sock.settimeout(None)
        self.messages = []
        self._lock = threading.Lock()
        self.closed = False
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self.send({"type": "auth", "username": username})
        if wait_welcome and not self.wait_for(
            lambda m: m.get("type") == "system" and "Welcome" in m.get("message", ""),
            timeout,
        ):
            raise AssertionError(f"{username}: no welcome message within {timeout}s")

    def _record(self, message):
        with self._lock:
            self.messages.append(message)

    def _read_loop(self):
        buffer = b""
        while True:
            try:
                data = self.sock.recv(4096)
            except OSError:
                break
            if not data:
                break
            buffer += data
            framed, buffer = receive_message(buffer)
            for raw in framed:
                try:
                    self._record(decrypt_message(raw))
                except ValueError:
                    self._record({"type": "_corrupt"})
        self.closed = True

    def snapshot(self):
        with self._lock:
            return list(self.messages)

    def send(self, payload):
        self.sock.sendall(encrypt_message(payload))

    def wait_for(self, predicate, timeout=5.0, start=0):
        found = []

        def match():
            for message in self.snapshot()[start:]:
                if predicate(message):
                    found.append(message)
                    return True
            return False

        wait_until(match, timeout)
        return found[0] if found else None

    def request_users(self, timeout=5.0):
        start = len(self.snapshot())
        self.send({"type": "command", "action": "/users"})
        return self.wait_for(lambda m: m.get("type") == "users_response", timeout, start)

    def users_matching(self, predicate, timeout=5.0):
        """Poll /users until predicate(set(users)); return the last list seen."""
        last = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            response = self.request_users()
            if response is not None:
                last = response.get("users", [])
                if predicate(set(last)):
                    return last
            time.sleep(0.1)
        return last

    def wait_closed(self, timeout=5.0):
        return wait_until(lambda: self.closed, timeout)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def close_abruptly(self):
        """Reset the connection (no FIN) to simulate a killed client."""
        try:
            self.sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )
        except OSError:
            pass
        self.close()


# --------------------------------------------------------------------------- #
# Server lifecycle
# --------------------------------------------------------------------------- #
def port_is_open():
    try:
        with socket.create_connection((HOST, PORT), timeout=0.25):
            return True
    except OSError:
        return False


def start_server():
    if port_is_open():
        raise SystemExit(
            "TCP 5555 is already in use. Stop the running server before testing."
        )
    log = open(SERVER_LOG, "w", encoding="utf-8")
    process = subprocess.Popen(
        [PYTHON, "-u", "server.py"],
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 10
    while time.time() < deadline:
        if process.poll() is not None:
            raise SystemExit(f"server exited during startup; see {SERVER_LOG}")
        if port_is_open():
            time.sleep(0.3)  # let the accept loop finish the readiness probe
            return process, log
        time.sleep(0.05)
    process.kill()
    raise SystemExit("server did not start listening on 5555")


def stop_server(process, log):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    log.close()


# --------------------------------------------------------------------------- #
# Phase 0: an idle pre-auth connection must not stall the server
# --------------------------------------------------------------------------- #
def run_preauth_phase():
    process, log = start_server()
    squatter = alice = None
    detail = ""
    try:
        squatter = socket.create_connection((HOST, PORT), timeout=5)
        squatter.recv(4096)  # read auth_request, then never send a username
        time.sleep(0.4)

        try:
            alice = RawClient("alice", timeout=6)
        except Exception as exc:
            alice = None
            detail = repr(exc)

        check(
            "login: an idle pre-auth connection does not block other logins",
            alice is not None,
            detail,
        )
        if alice is not None:
            users = alice.users_matching(lambda s: s == {"alice"}, 3)
            check(
                "login: half-open connection is not listed as an online user",
                users == ["alice"],
                str(users),
            )
    finally:
        if alice is not None:
            alice.close()
        if squatter is not None:
            squatter.close()
        stop_server(process, log)
        time.sleep(0.4)


# --------------------------------------------------------------------------- #
# Phase 1: raw protocol behaviour
# --------------------------------------------------------------------------- #
def run_raw_phase():
    process, log = start_server()
    clients = []
    try:
        alice = RawClient("alice")
        clients.append(alice)
        check(
            "login: alice welcomed",
            alice.wait_for(
                lambda m: m.get("type") == "system" and "Welcome alice" in m.get("message", ""),
                1,
            )
            is not None,
        )

        bob = RawClient("bob")
        clients.append(bob)
        alice.wait_for(
            lambda m: m.get("type") == "system" and "bob joined the chat." in m.get("message", "")
        )
        time.sleep(0.7)  # let any duplicate broadcast arrive

        alice_joins = [
            m for m in alice.snapshot() if "bob joined the chat." in m.get("message", "")
        ]
        bob_joins = [
            m for m in bob.snapshot() if "bob joined the chat." in m.get("message", "")
        ]
        check(
            "login: join notification seen exactly once (other client)",
            len(alice_joins) == 1,
            f"alice saw {len(alice_joins)}",
        )
        check(
            "login: join notification seen exactly once (joining client)",
            len(bob_joins) == 1,
            f"bob saw {len(bob_joins)}",
        )

        # -- duplicate username rejection ---------------------------------- #
        dup = RawClient("alice", wait_welcome=False)
        clients.append(dup)
        error = dup.wait_for(lambda m: m.get("type") == "error", 5)
        check(
            "duplicate username: rejected with a helpful error",
            error is not None and "already taken" in error.get("message", ""),
            str(error),
        )
        check("duplicate username: rejected connection is closed", dup.wait_closed(5))
        time.sleep(0.3)
        users = alice.users_matching(lambda s: s == {"alice", "bob"}, 3)
        check(
            "duplicate username: session table still has one alice",
            users is not None and sorted(users) == ["alice", "bob"],
            str(users),
        )
        alice.send({"type": "chat", "message": "still connected"})
        check(
            "duplicate username: original session still works",
            bob.wait_for(
                lambda m: m.get("type") == "chat" and m.get("message") == "still connected"
            )
            is not None,
        )

        # -- chat ---------------------------------------------------------- #
        bob.send({"type": "chat", "message": "hello alice"})
        message = alice.wait_for(
            lambda m: m.get("type") == "chat" and m.get("message") == "hello alice"
        )
        check(
            "chat: delivered to the other client with the sender name",
            message is not None and message.get("username") == "bob",
            str(message),
        )
        check(
            "chat: not duplicated",
            len(
                [
                    m
                    for m in alice.snapshot()
                    if m.get("type") == "chat" and m.get("message") == "hello alice"
                ]
            )
            == 1,
        )

        # -- /users -------------------------------------------------------- #
        users = bob.users_matching(lambda s: True, 3)
        check(
            "/users: reports exactly the connected usernames",
            users is not None and sorted(users) == ["alice", "bob"],
            str(users),
        )
        check(
            "/users: no duplicate entries",
            users is not None and len(users) == len(set(users)),
            str(users),
        )

        # -- /quit --------------------------------------------------------- #
        bob.send({"type": "command", "action": "/quit"})
        check("/quit: server closes the connection", bob.wait_closed(5))
        alice.wait_for(lambda m: "bob left the chat." in m.get("message", ""), 5)
        time.sleep(0.7)
        notices = [
            m for m in alice.snapshot() if "bob left the chat." in m.get("message", "")
        ]
        check(
            "/quit: exactly one leave notification",
            len(notices) == 1,
            f"alice saw {len(notices)}",
        )
        users = alice.users_matching(lambda s: s == {"alice"}, 5)
        check("/quit: username removed from /users", users == ["alice"], str(users))
        check(
            "/users: count matches the list",
            users is not None and len(users) == 1,
            str(users),
        )

        # -- unexpected disconnect ----------------------------------------- #
        dave = RawClient("dave")
        clients.append(dave)
        alice.wait_for(lambda m: "dave joined the chat." in m.get("message", ""), 5)
        dave.close_abruptly()
        users = alice.users_matching(lambda s: s == {"alice"}, 8)
        check(
            "disconnect: abrupt close removes the session from /users",
            users == ["alice"],
            str(users),
        )
        time.sleep(0.7)
        dave_notices = [
            m
            for m in alice.snapshot()
            if "dave" in m.get("message", "")
            and ("left the chat." in m["message"] or "disconnected" in m["message"])
        ]
        check(
            "disconnect: exactly one disconnect notification",
            len(dave_notices) == 1,
            str([m.get("message") for m in dave_notices]),
        )
        check(
            "disconnect: stale username is not kept in the session table",
            alice.users_matching(lambda s: "dave" not in s, 3) == ["alice"],
        )

        # -- username can be reused after a clean disconnect --------------- #
        dave2 = RawClient("dave")
        clients.append(dave2)
        check(
            "disconnect: username reusable after leaving",
            dave2.wait_for(
                lambda m: m.get("type") == "system" and "Welcome dave" in m.get("message", ""),
                1,
            )
            is not None,
        )

        # -- rapid leave/rejoin must not corrupt the session table ---------- #
        racer = RawClient("racer")
        clients.append(racer)
        problems = []
        for attempt in range(8):
            racer.send({"type": "command", "action": "/quit"})
            if not racer.wait_closed(5):
                problems.append((attempt, "quit did not close socket"))
                break
            racer = RawClient("racer")
            clients.append(racer)
            users = alice.users_matching(lambda s: "racer" in s, 3)
            if users is None or users.count("racer") != 1:
                problems.append((attempt, users))
        check(
            "session table: rapid leave/rejoin keeps exactly one live 'racer'",
            not problems,
            str(problems),
        )

        # -- invalid commands ---------------------------------------------- #
        start = len(alice.snapshot())
        alice.send({"type": "command", "action": "/user"})
        error = alice.wait_for(
            lambda m: m.get("type") == "error" and "supported" in m.get("message", "").lower(),
            5,
            start,
        )
        check(
            "invalid command: /user gets a helpful error",
            error is not None,
            str(error),
        )

        start = len(dave2.snapshot())
        dave2.send({"type": "command", "action": "/users,"})
        error = dave2.wait_for(
            lambda m: m.get("type") == "error" and "supported" in m.get("message", "").lower(),
            5,
            start,
        )
        check(
            "invalid command: /users, gets a helpful error",
            error is not None,
            str(error),
        )

        # Commands typed as chat text (older client) must not be broadcast.
        start_a = len(alice.snapshot())
        start_d = len(dave2.snapshot())
        dave2.send({"type": "message", "text": "/user"})
        dave2.send({"type": "chat", "message": "/users,"})
        error = dave2.wait_for(
            lambda m: m.get("type") == "error" and "supported" in m.get("message", "").lower(),
            5,
            start_d,
        )
        check(
            "invalid command: slash text in a chat frame is answered as a command",
            error is not None,
            str(error),
        )
        time.sleep(0.5)
        leaked = [
            m.get("message", "")
            for m in alice.snapshot()[start_a:]
            if m.get("type") == "chat" and m.get("message", "").startswith("/")
        ]
        check(
            "invalid command: never broadcast as ordinary chat",
            not leaked,
            str(leaked),
        )

        # -- command case-insensitivity ------------------------------------ #
        start = len(alice.snapshot())
        alice.send({"type": "command", "action": "/USERS"})
        check(
            "command: /USERS handled case-insensitively",
            alice.wait_for(lambda m: m.get("type") == "users_response", 5, start) is not None,
        )

    finally:
        for client in clients:
            client.close()
        stop_server(process, log)
        time.sleep(0.4)


# --------------------------------------------------------------------------- #
# Phase 2: end-to-end through the real client.py
# --------------------------------------------------------------------------- #
class ClientProcess:
    """Runs client.py with piped stdin/stdout and collects its output."""

    def __init__(self, username):
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        self.process = subprocess.Popen(
            [PYTHON, "-u", "client.py"],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
        self.output = ""
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self.send_line(username)

    def _read_loop(self):
        for line in self.process.stdout:
            with self._lock:
                self.output += line

    def text(self):
        with self._lock:
            return self.output

    def send_line(self, line):
        try:
            self.process.stdin.write(line + "\n")
            self.process.stdin.flush()
        except (OSError, ValueError):
            pass

    def wait_for(self, needle, timeout=10.0):
        return wait_until(lambda: needle in self.text(), timeout, interval=0.05)

    def count(self, needle):
        return self.text().count(needle)

    def wait_exit(self, timeout=10.0):
        try:
            self.process.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def stop(self):
        try:
            self.process.kill()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Phase 3: one wedged client must not freeze session accounting
# --------------------------------------------------------------------------- #
def run_slow_reader_phase():
    process, log = start_server()
    holder = checker = flood = None
    try:
        # Login, then never read from the socket again.
        holder = socket.create_connection((HOST, PORT), timeout=5)
        holder.recv(4096)
        holder.sendall(encrypt_message({"type": "auth", "username": "holder"}))
        time.sleep(0.4)

        checker = RawClient("checker")
        flood = RawClient("flood")
        payload = "x" * 32768

        def spam():
            for _ in range(60):
                try:
                    flood.send({"type": "chat", "message": payload})
                except Exception:
                    return

        threading.Thread(target=spam, daemon=True).start()
        time.sleep(2.5)  # fill the non-reading client's buffers

        start = len(checker.snapshot())
        began = time.time()
        checker.send({"type": "command", "action": "/users"})
        response = checker.wait_for(
            lambda m: m.get("type") == "users_response", 6, start
        )
        check(
            "thread safety: /users answers while a client is not reading",
            response is not None,
            f"no reply within {time.time() - began:.1f}s",
        )
        check(
            "/users: non-reading client listed exactly once",
            response is not None and response.get("users", []).count("holder") == 1,
            str(response),
        )

        holder.close()
        users = checker.users_matching(lambda s: "holder" not in s, 8)
        check(
            "disconnect: wedged client is reaped once its socket fails",
            users is not None and "holder" not in users,
            str(users),
        )

    finally:
        for client in (checker, flood):
            if client is not None:
                client.close()
        if holder is not None:
            try:
                holder.close()
            except OSError:
                pass
        stop_server(process, log)
        time.sleep(0.4)


def last_users_line(text):
    lines = [line for line in text.splitlines() if "=== Online users" in line]
    return lines[-1] if lines else ""


def run_e2e_phase():
    process, log = start_server()
    erin = frank = None
    try:
        erin = ClientProcess("erin")
        check("e2e: erin logs in", erin.wait_for("Welcome erin"))

        dup = ClientProcess("erin")
        check("e2e: duplicate username rejected", dup.wait_for("already taken", 10))
        check("e2e: rejected duplicate client exits", dup.wait_exit(10))
        dup.stop()

        frank = ClientProcess("frank")
        check("e2e: frank logs in", frank.wait_for("Welcome frank"))

        check("e2e: erin notified that frank joined", erin.wait_for("frank joined the chat."))
        time.sleep(1.2)
        check(
            "e2e: exactly one join notification for frank",
            erin.count("frank joined the chat.") == 1,
            f"erin saw {erin.count('frank joined the chat.')}",
        )

        frank.send_line("/users")
        check("e2e: /users responds", frank.wait_for("=== Online users"))
        time.sleep(0.5)
        users_line = [
            line for line in frank.text().splitlines() if "=== Online users" in line
        ]
        check(
            "e2e: /users lists the real connected set",
            bool(users_line)
            and "erin" in users_line[-1]
            and "frank" in users_line[-1]
            and "(2)" in users_line[-1],
            str(users_line),
        )

        erin.send_line("hello from erin")
        check("e2e: chat delivered", frank.wait_for("[erin]: hello from erin"))

        frank.send_line("/user")
        check(
            "e2e: invalid /user answered with an error",
            frank.wait_for("Supported commands", 5),
            frank.text()[-200:],
        )
        frank.send_line("/users,")
        time.sleep(1.0)
        check(
            "e2e: slash text is not echoed to the room as chat",
            "[frank]: /user" not in erin.text()
            and "[frank]: /users," not in erin.text(),
            erin.text()[-200:],
        )

        frank.send_line("/quit")
        check("e2e: /quit makes the client exit", frank.wait_exit(10))
        check("e2e: erin notified that frank left", erin.wait_for("frank left the chat."))
        erin.send_line("/users")
        check(
            "e2e: /users no longer lists the departed client",
            wait_until(lambda: "=== Online users (1)" in last_users_line(erin.text()), 8, 0.2)
            and "erin" in last_users_line(erin.text())
            and "frank" not in last_users_line(erin.text()),
            last_users_line(erin.text()) or erin.text()[-300:],
        )

        erin.send_line("/quit")
        check("e2e: erin exits cleanly", erin.wait_exit(10))

    finally:
        for client in (erin, frank):
            if client is not None:
                client.stop()
        stop_server(process, log)
        time.sleep(0.4)


def main():
    print("=== Phase 0: idle pre-auth connection ===")
    run_preauth_phase()
    print("\n=== Phase 1: raw protocol / server behaviour ===")
    run_raw_phase()
    print("\n=== Phase 2: end-to-end with client.py ===")
    run_e2e_phase()
    print("\n=== Phase 3: wedged client / thread safety ===")
    run_slow_reader_phase()

    print(f"\n{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
    if FAILURES:
        print("Failed checks:")
        for name in FAILURES:
            print(f"  - {name}")
        if os.path.exists(SERVER_LOG):
            with open(SERVER_LOG, encoding="utf-8", errors="replace") as handle:
                tail = handle.read().strip()
            if tail:
                print("\nLast server log:")
                print(tail[-2000:])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
