import base64
import json
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app, db
from app.crypto import generate_user_keypair, initialize_root_ca, issue_user_certificate
from app.models import Certificate, CertificateLoginChallenge, CertificateStatus, User
from app.routes.auth import generate_token


def run_demo():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        user = User(username="demo", email="demo@example.com", password_hash="demo")
        db.session.add(user)
        db.session.flush()

        ca_private_key, ca_certificate = initialize_root_ca(
            str(PROJECT_ROOT / "keys" / "ca_key.pem"),
            str(PROJECT_ROOT / "keys" / "ca_cert.pem"),
        )
        private_key, public_key = generate_user_keypair()
        certificate = issue_user_certificate(user, public_key, ca_private_key, ca_certificate)
        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")
        cert_record = Certificate(
            user_id=user.id,
            serial_number=str(certificate.serial_number),
            certificate_pem=cert_pem,
            public_key_pem=public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8"),
            status=CertificateStatus.ACTIVE,
            expiry_date=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db.session.add(cert_record)
        db.session.flush()

        challenge = CertificateLoginChallenge(
            user_id=user.id,
            nonce=secrets.token_urlsafe(16),
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            used=False,
        )
        db.session.add(challenge)
        db.session.commit()

        signature = private_key.sign(
            challenge.nonce.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        signature_b64 = base64.b64encode(signature).decode("utf-8")
        print(json.dumps({
            "message": "demo challenge created",
            "nonce": challenge.nonce,
            "signature_b64": signature_b64,
            "certificate_pem": cert_pem,
            "token": generate_token(user),
        }, indent=2))


if __name__ == "__main__":
    run_demo()
