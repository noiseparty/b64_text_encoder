import base64
import os
from flask import Flask, render_template, request, jsonify
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_text(plaintext: str, password: str) -> str:
    """Encrypt plaintext using password-derived key."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(plaintext.encode())
    # Combine salt + encrypted data and encode as base64
    combined = base64.urlsafe_b64encode(salt + encrypted)
    return combined.decode()


def decrypt_text(encrypted_text: str, password: str) -> str:
    """Decrypt text using password-derived key."""
    # Decode and split salt from encrypted data
    combined = base64.urlsafe_b64decode(encrypted_text.encode())
    salt = combined[:16]
    encrypted = combined[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)
    return decrypted.decode()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    plaintext = data.get("text", "")
    password = data.get("password", "")

    if not plaintext:
        return jsonify({"error": "Please enter text to encrypt"}), 400
    if not password:
        return jsonify({"error": "Please enter a password"}), 400

    try:
        encrypted = encrypt_text(plaintext, password)
        return jsonify({"result": encrypted})
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500


@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json()
    encrypted_text = data.get("text", "")
    password = data.get("password", "")

    if not encrypted_text:
        return jsonify({"error": "Please enter text to decrypt"}), 400
    if not password:
        return jsonify({"error": "Please enter a password"}), 400

    try:
        decrypted = decrypt_text(encrypted_text, password)
        return jsonify({"result": decrypted})
    except InvalidToken:
        return jsonify({"error": "Decryption failed: Wrong password or corrupted data"}), 400
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500


if __name__ == "__main__":
    print("Starting Encryption Tool...")
    print("Open http://localhost:5000 in your browser")
    app.run(debug=True, port=5000)
