from argon2 import PasswordHasher as Argon2Hasher
from argon2.exceptions import (
    HashingError,
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

from src.core.protocols import PasswordHasherProtocol


class Argon2PasswordHasher(PasswordHasherProtocol):
    def __init__(self):
        self._hasher = Argon2Hasher(
            time_cost=3,          # количество итераций
            memory_cost=65536,    # 64 MB
            parallelism=4,        # 4 потока
            hash_len=32,          # длина хеша
            salt_len=16,          # длина соли
        )

    def hash(self, password: str) -> str:
        try:
            return self._hasher.hash(password)
        except HashingError as e:
            raise RuntimeError(f"Password hashing failed: {e}") from e

    def verify(self, password: str, hash: str) -> bool:
        try:
            return self._hasher.verify(hash, password)
        except VerifyMismatchError:
            return False
        except (InvalidHashError, VerificationError):
            return False

    def needs_rehash(self, hash: str) -> bool:
        return self._hasher.check_needs_rehash(hash)