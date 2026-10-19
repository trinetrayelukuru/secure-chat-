import json
import os

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

# Load the shared Fernet key from the .env file.
# The server and every client must use the SAME key.
load_dotenv()

KEY = os.environ["SECURECHAT_KEY"]
cipher = Fernet(KEY)


def encrypt_message(message: dict) -> bytes:
    """Convert a dictionary to JSON and encrypt it."""
    json_data = json.dumps(message).encode("utf-8")
    encrypted_data = cipher.encrypt(json_data)

    # Newline marks the end of one message.
    return encrypted_data + b"\n"


def decrypt_message(encrypted_data: bytes) -> dict:
    """Decrypt a Fernet token and convert JSON to a dictionary."""
    encrypted_data = encrypted_data.strip()

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("Invalid or corrupted message") from error


def receive_message(buffer: bytes):
    """Extract complete newline-terminated messages from a buffer."""
    messages = []

    while b"\n" in buffer:
        message, buffer = buffer.split(b"\n", 1)

        if message:
            messages.append(message)

    return messages, buffer