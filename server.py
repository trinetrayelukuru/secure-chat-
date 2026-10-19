import socket
import sys
import threading

import ui
from protocol import encrypt_message, decrypt_message, receive_message

HOST = "0.0.0.0"  # Accept connections from any interface
PORT = 5555

# username -> connected socket. Every mutation happens under client_lock.
clients: dict[str, socket.socket] = {}
client_lock = threading.Lock()

SUPPORTED_COMMANDS = ("/users", "/quit")


def close_connection(conn: socket.socket) -> None:
    """Close a socket without letting a shutdown error escape."""
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass


def send_message(conn: socket.socket, message: dict) -> bool:
    """Encrypt and send one framed message. False if the socket is unusable."""
    try:
        conn.sendall(encrypt_message(message))
        return True
    except (ConnectionError, OSError):
        return False


def remove_session(username: str, conn: socket.socket) -> bool:
    """Remove exactly this connection's session from the shared table.

    The identity check means a late disconnect can never delete a newer
    session that re-used the same username. Returns True only for the caller
    that actually removed the session, so cleanup and the leave notification
    happen exactly once.
    """
    with client_lock:
        if clients.get(username) is not conn:
            return False
        del clients[username]
    close_connection(conn)
    return True


def online_count() -> int:
    """Number of registered sessions, read under the session lock."""
    with client_lock:
        return len(clients)


def _send_to_all(payload: dict, exclude_username: str = None):
    """Snapshot the table under the lock, then send outside the lock.

    Holding client_lock during sendall() lets one client that stops reading
    block every handler (including /users) indefinitely, so the lock must only
    ever guard the dict itself.
    """
    with client_lock:
        targets = [
            (username, conn)
            for username, conn in clients.items()
            if username != exclude_username
        ]

    data = encrypt_message(payload)
    failed = []
    for username, conn in targets:
        try:
            conn.sendall(data)
        except (ConnectionError, OSError):
            failed.append((username, conn))
    return failed


def broadcast(message: dict, exclude_username: str = None) -> list:
    """Send a message to every registered client.

    Sockets that fail are removed exactly once (identity checked) and the
    remaining clients get a single departure notice for each of them. Failed
    sends during a departure notice are handled by the same loop rather than
    by recursion, so every client is announced at most once.
    """
    removed = []
    pending = [(message, exclude_username)]

    while pending:
        payload, exclude = pending.pop(0)
        for username, conn in _send_to_all(payload, exclude):
            if remove_session(username, conn):
                removed.append(username)
                ui.event(
                    "warn",
                    f"{username} dropped (send failed)",
                    f"{online_count()} online",
                )
                pending.append(
                    (
                        {
                            "type": "system",
                            "message": f"{username} has disconnected unexpectedly",
                        },
                        None,
                    )
                )
    return removed


def handle_command(action: str, username: str, conn: socket.socket) -> bool:
    """Run a slash command. Returns False when the client asked to quit."""
    command = action.strip().split(" ", 1)[0].lower() if isinstance(action, str) else ""

    if command == "/users":
        with client_lock:
            online_users = sorted(clients)
        send_message(conn, {"type": "users_response", "users": online_users})
        return True

    if command == "/quit":
        return False

    send_message(
        conn,
        {
            "type": "error",
            "message": (
                f"Unknown command '{action}'. "
                f"Supported commands: {', '.join(SUPPORTED_COMMANDS)}."
            ),
        },
    )
    return True


def handle_payload(payload: dict, username: str, conn: socket.socket) -> bool:
    """Handle one decrypted client message. Returns False when it quits."""
    message_type = payload.get("type")
    text = payload.get("message", payload.get("text", ""))

    if message_type == "command":
        return handle_command(payload.get("action", ""), username, conn)

    if message_type in ("chat", "message"):
        # Commands must never fall through to the chat broadcast, even when a
        # client sends them as ordinary text.
        if isinstance(text, str) and text.lstrip().startswith("/"):
            return handle_command(text, username, conn)
        broadcast({"type": "chat", "username": username, "message": text})
        return True

    send_message(conn, {"type": "error", "message": "Unsupported message type."})
    return True


def handle_client(username: str, conn: socket.socket, addr) -> str:
    """Serve a logged-in client until it disconnects. Returns the leave reason."""
    if not send_message(
        conn,
        {
            "type": "system",
            "message": f"Welcome {username}! Use /users to see online users.",
        },
    ):
        return "has disconnected unexpectedly"

    # Exactly one join notification per successful login. This is the only
    # place a join is announced; the joining client receives it too.
    broadcast({"type": "system", "message": f"{username} joined the chat."})

    buffer = b""
    while True:
        try:
            data = conn.recv(4096)
        except (ConnectionError, OSError):
            return "has disconnected unexpectedly"

        if not data:
            return "left the chat."

        buffer += data
        messages, buffer = receive_message(buffer)

        for raw in messages:
            try:
                payload = decrypt_message(raw)
            except ValueError:
                send_message(
                    conn, {"type": "error", "message": "Invalid or corrupted message"}
                )
                continue

            if not isinstance(payload, dict):
                send_message(
                    conn, {"type": "error", "message": "Invalid message format"}
                )
                continue

            if not handle_payload(payload, username, conn):
                return "left the chat."


def read_username(conn: socket.socket):
    """Read the auth frame. Returns the username, or None if the client left."""
    buffer = b""
    while True:
        try:
            chunk = conn.recv(1024)
        except (ConnectionError, OSError):
            return None

        if not chunk:
            return None

        buffer += chunk
        messages, buffer = receive_message(buffer)

        for raw in messages:
            try:
                payload = decrypt_message(raw)
            except ValueError:
                send_message(
                    conn, {"type": "error", "message": "Invalid username message"}
                )
                return None

            if (
                isinstance(payload, dict)
                and payload.get("type") == "auth"
                and "username" in payload
            ):
                username = str(payload["username"]).strip()
                return username or None


def serve_connection(conn: socket.socket, addr) -> None:
    """Authenticate one connection, handle it, and clean up in one place."""
    username = None
    registered = False
    reason = "has disconnected unexpectedly"

    try:
        if not send_message(
            conn, {"type": "auth_request", "message": "Please provide your username:"}
        ):
            return

        username = read_username(conn)
        if not username:
            return

        with client_lock:
            if username in clients:
                duplicate = True
            else:
                clients[username] = conn
                duplicate = False

        if duplicate:
            send_message(
                conn,
                {
                    "type": "error",
                    "message": f"Username '{username}' is already taken. Please choose another.",
                },
            )
            ui.event(
                "warn",
                f"duplicate username '{username}' rejected from {addr[0]}",
            )
            return

        registered = True
        ui.event(
            "join",
            f"{username} joined from {addr[0]}",
            f"{online_count()} online",
        )
        reason = handle_client(username, conn, addr)

    except (ConnectionError, OSError) as error:
        ui.event("error", f"connection error for {addr}: {error}")

    except Exception as error:  # never leave a registered socket behind
        ui.event("error", f"client {addr} failed: {error}")

    finally:
        if registered and remove_session(username, conn):
            # Only the caller that actually removed the session announces it,
            # so a disconnect is never broadcast twice.
            broadcast({"type": "system", "message": f"{username} {reason}"})
            ui.event(
                "leave",
                f"{username} {reason.rstrip('.')}",
                f"{online_count()} online",
            )
        elif not registered:
            close_connection(conn)


def start_server():
    """Start the TCP chat server."""
    ui.banner("server", PORT)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(10)  # Allow multiple pending connections

        ui.server_panel(HOST, PORT)
        ui.event("ready", "server ready - waiting for clients")

        while True:
            conn, addr = server.accept()
            # The username handshake runs in this connection's own thread, so a
            # client that connects and never sends a username cannot block
            # every other login.
            threading.Thread(
                target=serve_connection,
                args=(conn, addr),
                daemon=True,
            ).start()


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        ui.event("info", "server shutting down")
    except Exception as e:
        ui.event("error", f"server stopped: {e}")
        sys.exit(1)
