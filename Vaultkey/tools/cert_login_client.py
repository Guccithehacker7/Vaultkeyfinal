import base64
import json
import os
import urllib.request
from getpass import getpass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def prompt(text: str) -> str:
    return input(text).strip()


def load_private_key(path: str):
    data = open(path, "rb").read()
    try:
        return serialization.load_pem_private_key(data, password=None)
    except TypeError:
        password = getpass("Enter private key passphrase: ")
        return serialization.load_pem_private_key(data, password=password.encode("utf-8"))


def request_json(url: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as response:
        body = response.read().decode("utf-8")
        return response.status, json.loads(body) if body else {}


def main():
    server_url = prompt("Server URL (e.g. http://127.0.0.1:5000): ")
    username_or_email = prompt("Username or email: ")
    private_key_path = prompt("Path to private key PEM file: ")
    certificate_path = prompt("Path to certificate PEM file: ")

    if not os.path.exists(private_key_path):
        print("Private key file not found")
        return
    if not os.path.exists(certificate_path):
        print("Certificate file not found")
        return

    private_key = load_private_key(private_key_path)
    certificate_pem = open(certificate_path, "r", encoding="utf-8").read()

    status, challenge_payload = request_json(
        f"{server_url.rstrip('/')}/api/auth/certificate/challenge",
        {"username_or_email": username_or_email},
    )
    if status != 200:
        print("Challenge failed:", challenge_payload.get("message", challenge_payload))
        return

    nonce = challenge_payload.get("nonce")
    if not nonce:
        print("No nonce returned")
        return

    signature = private_key.sign(
        nonce.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    status, verify_payload = request_json(
        f"{server_url.rstrip('/')}/api/auth/certificate/verify",
        {
            "username_or_email": username_or_email,
            "certificate_pem": certificate_pem,
            "nonce": nonce,
            "signature": signature_b64,
        },
    )

    if status == 200:
        print("Login succeeded")
        print(json.dumps(verify_payload, indent=2))
    else:
        print("Login failed:", verify_payload.get("message", verify_payload))


if __name__ == "__main__":
    main()
