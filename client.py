import socket
import sys
import threading

import ui
from protocol import encrypt_message, decrypt_message, receive_message

# Configuration
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5555

# Commands are decided by the server; the client only forwards slash input.
LOCAL_COMMANDS = ("/quit",)


def emit(line, prompt_after=True):
    """Print one incoming line above the input prompt, without clearing the screen."""
    if ui.COLOR:
        text = "\r\x1b[K" + line + "\n"
    else:
        text = "\r" + line + "\n"
    if prompt_after:
        text += ui.prompt()
    # One locked write so a server event can never be split by the prompt or
    # by another line arriving on the receive thread.
    ui.write(text)


def send_messages(conn, username):
    """Thread to read user input and send encrypted messages."""
    while True:
        try:
            user_input = input(ui.prompt())
        except (EOFError, KeyboardInterrupt):
            # Send quit and exit
            try:
                conn.sendall(encrypt_message({"type": "command", "action": "/quit"}))
            except Exception:
                pass
            break

        text = user_input.strip()

        # Every slash-prefixed line is a command. Unknown ones go to the
        # server, which replies with a helpful error instead of broadcasting
        # the line as chat.
        if text.startswith("/"):
            command = text.split(" ", 1)[0].lower()
            try:
                conn.sendall(encrypt_message({"type": "command", "action": text}))
            except Exception:
                break

            if command in LOCAL_COMMANDS:
                break
        else:
            try:
                conn.sendall(encrypt_message({"type": "chat", "message": user_input}))
            except Exception:
                break


def receive_messages(conn):
    """Thread to receive and decrypt messages from server."""
    buffer = b""
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                emit(ui.system_line("connection closed by the server"), False)
                break

            buffer += data
            messages, buffer = receive_message(buffer)

            for msg in messages:
                try:
                    decrypted = decrypt_message(msg)
                except ValueError:
                    emit(ui.error_line("invalid or corrupted message from server"))
                    continue

                # Handle server responses
                if decrypted.get("type") == "system":
                    emit(ui.system_line(decrypted.get("message", "")))
                elif decrypted.get("type") == "error":
                    emit(ui.error_line(decrypted.get("message", "")))
                elif decrypted.get("type") == "users_response":
                    users = decrypted.get("users", [])
                    emit(ui.users_line(users))
                elif decrypted.get("type") == "chat":
                    user = decrypted.get("username", "unknown")
                    text = decrypted.get("message", "")
                    emit(ui.chat_line(user, text))
                elif decrypted.get("type") == "auth_request":
                    # Server asking for username - shouldn't happen in normal flow
                    pass
                else:
                    emit(ui.system_line(str(decrypted)))

        except (ConnectionError, OSError, BrokenPipeError):
            emit(ui.error_line("connection lost"), False)
            break
        except Exception as e:
            emit(ui.error_line(f"receive error: {e}"), False)
            break


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST

    ui.banner("client", DEFAULT_PORT)
    ui.help_panel()
    print()
    ui.client_panel(host, DEFAULT_PORT)

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((host, DEFAULT_PORT))
    except ConnectionRefusedError:
        ui.connection_failed(host, DEFAULT_PORT, "nothing is listening")
        sys.exit(1)
    except Exception as e:
        ui.connection_failed(host, DEFAULT_PORT, str(e))
        sys.exit(1)

    ui.event("ready", f"connected to {host}:{DEFAULT_PORT}")

    # Ask for username
    username = input(ui.input_prompt("username")).strip()
    while not username:
        username = input(ui.input_prompt("username")).strip()

    # Send encrypted auth message to server
    try:
        conn.sendall(encrypt_message({"type": "auth", "username": username}))
    except Exception:
        ui.event("error", "could not send the username to the server")
        sys.exit(1)

    ui.event("info", f"signing in as {username}")

    # Start receive thread first so the welcome / duplicate-username error is
    # processed even while the user is still at the prompt.
    receive_thread = threading.Thread(target=receive_messages, args=(conn,), daemon=True)
    receive_thread.start()

    # Start send thread
    send_thread = threading.Thread(target=send_messages, args=(conn, username), daemon=True)
    send_thread.start()

    # The client lives as long as the connection does. When the server closes
    # it (or the receive loop fails), close our side and exit so the server
    # never keeps a session for a client that is gone.
    try:
        receive_thread.join()
    except KeyboardInterrupt:
        ui.event("info", "disconnecting")
        try:
            conn.sendall(encrypt_message({"type": "command", "action": "/quit"}))
        except Exception:
            pass

    try:
        conn.close()
    except OSError:
        pass


if __name__ == "__main__":
    main()
