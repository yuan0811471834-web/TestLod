from flask import Flask, jsonify
import hashlib
import hmac
import secrets
import string
import time

app = Flask(__name__)
# แสดง JSON ตามลำดับที่เขียนไว้ใน Dictionary
app.json.sort_keys = False

WORK_FACTOR = 2_000_000 ##---------##
PASSWORD_LENGTH = 10
SALT_SIZE_BYTES = 16


def generate_random_password(length: int) -> str:
    characters = string.ascii_letters + string.digits

    return "".join(
        secrets.choice(characters)
        for _ in range(length)
    )


USERNAME = "demo_user"
USER_PASSWORD = generate_random_password(PASSWORD_LENGTH)
PASSWORD_SALT = secrets.token_bytes(SALT_SIZE_BYTES)

STORED_PASSWORD_HASH = hashlib.pbkdf2_hmac(
    "sha256",
    USER_PASSWORD.encode("utf-8"),
    PASSWORD_SALT,
    WORK_FACTOR
)


@app.route("/")
def home():
    return "Server is running..."


@app.route("/login-check")
def login_check():
    start_time = time.perf_counter()

    entered_password = USER_PASSWORD

    calculated_password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        entered_password.encode("utf-8"),
        PASSWORD_SALT,
        WORK_FACTOR
    )

    password_is_valid = hmac.compare_digest(
        calculated_password_hash,
        STORED_PASSWORD_HASH
    )

    execution_time = time.perf_counter() - start_time

    return jsonify({
        "username": USERNAME,
        "entered_password": entered_password,
        "password_length": len(entered_password),

        "salt_hex": PASSWORD_SALT.hex(),
        "salt_size_bits": len(PASSWORD_SALT) * 8,
        "algorithm": "PBKDF2-HMAC-SHA256",
        "work_factor": WORK_FACTOR,

        "calculated_password_hash":
            calculated_password_hash.hex(),
        "stored_password_hash":
            STORED_PASSWORD_HASH.hex(),
        "hash_size_bits":
            len(calculated_password_hash) * 8,
        "password_valid": password_is_valid,
        "execution_time_seconds":
            round(execution_time, 4),
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8080,
        debug=False
    )
