import base64
import io

import pyotp
import qrcode
from cryptography.fernet import Fernet

from src.config import settings
from src.core.protocols import TOTPServiceProtocol


class TOTPService(TOTPServiceProtocol):
    def __init__(self):
        self._fernet = Fernet(
            settings.TOTP_ENCRYPTION_KEY.get_secret_value().encode()
        )

    def generate_secret(self) -> str:
        return pyotp.random_base32()

    def encrypt_secret(self, secret: str) -> str:
        return self._fernet.encrypt(secret.encode()).decode()

    def decrypt_secret(self, encrypted: str) -> str:
        return self._fernet.decrypt(encrypted.encode()).decode()

    def generate_uri(self, secret: str, email: str) -> str:
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=email,
            issuer_name=settings.TOTP_ISSUER_NAME,
        )

    def generate_qr_base64(self, uri: str) -> str:
        img = qrcode.make(uri)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        return base64.b64encode(buffer.getvalue()).decode()

    def verify_code(self, secret: str, code: str) -> bool:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=settings.TOTP_VALID_WINDOW)