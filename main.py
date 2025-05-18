from abc import ABC, abstractmethod
import cryptography
import os
from PIL import Image
from typing import Any

with open("config.env", "r") as f:
    config = f.read()

class Cipher(ABC):
    @abstractmethod
    def encrypt(self, message: str, key: Any) -> Any:
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext: Any, key: Any) -> str:
        pass
    
    @abstractmethod
    def validate_key(self, key: Any) -> bool:
        pass

class AbstractCipher(Cipher):
    def validate_key(self, key: Any) -> bool:
        return True

class KeyManager:
    def generate_RSA_keys(self):
        return {f"private_key": "{private_key}", "public_key": "{public_key}"} 
    def generate_ECC_keys(self):
        return {f"private_key": "{private_key}", "public_key": "{public_key}"}
    

class CipherRSA(AbstractCipher):

    def encrypt(self, message: str, public_key: int) -> bytes:
        return

    def decrypt(self, ciphertext: bytes, private_key: int) -> str:
        return


class CipherECC(AbstractCipher):
    def __init__(self, message):
        super().__init__(message)
        self.keys = KeyManager().generate_ECC_keys()

    def encrypt(self, message: str, public_key: str) -> bytes:
        return

    def decrypt(self, ciphertext: bytes, private_key: str) -> str:
        return

    def generate_keys(self):
        return
    

class CaesarCipher(Cipher):
    def __init__(self, message: str, shift: int):
        super().__init__(message)
        self.shift = shift

    def encrypt(self, message: str, key: int) -> str:
        return

    def decrypt(self, ciphertext: str, key: int) -> str:
        return

    def validate_key(self) -> bool:
        return


class VigenereCipher(Cipher):
    def __init__(self, message: str, key: str):
        super().__init__(message)
        self.key = key

    def encrypt(self, message: str, key: str) -> str:
        return

    def decrypt(self, ciphertext: str, key: str) -> str:
        return

    def validate_key(self) -> bool:
        return


class Base64Cipher(AbstractCipher):
    def __init__(self, message: str):
        super().__init__(message)

    def encrypt(self, message: str) -> str:
        return
    def decrypt(self, ciphertext: str) -> str:
        return
class SteganographyCipher(Cipher):
    def __init__(self, message: str, image_path: str):
        super().__init__(message)
        self.image_path = image_path

    def encrypt(self, message: str, image_path: str) -> str:
        return
    def decrypt(self, ciphertext: str, image_path: str) -> str:
        return
    def validate_key(self) -> bool:
        return