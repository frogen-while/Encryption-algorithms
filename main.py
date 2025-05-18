from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization 
import os
from PIL import Image
from typing import Any


class Cipher(ABC):
    @abstractmethod
    def encrypt(self, text: str, key: Any) -> Any:
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext: Any, key: Any) -> str:
        pass
    
    @abstractmethod
    def validate_key(self, key: Any) -> bool:
        return True


class KeyManager:
    def generate_RSA_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=None
        )
        public_key = private_key.public_key()
        return private_key, public_key
    def generate_ECC_keys(self):
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=None
        )
        public_key = private_key.public_key()
        return private_key, public_key

class CipherRSA(Cipher):

    def encrypt(self, text: str, public_key: rsa.RSAPublicKey) -> bytes:
        return

    def decrypt(self, ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> str:
        return

    def validate_key(self, key: Any) -> bool:
        return isinstance(key, rsa.RSAPublicKey) or isinstance(key, rsa.RSAPrivateKey)


class CipherECC(Cipher):

    def encrypt(self, text: str, public_key: ec.ECPublicKey) -> bytes:
        return

    def decrypt(self, ciphertext: bytes, private_key: ec.ECPrivateKey) -> str:
        return

    def validate_key(self, key: Any) -> bool:
        return isinstance(key, ec.EllipticCurvePublicKey) or isinstance(key, ec.EllipticCurvePrivateKey)

class CaesarCipher(Cipher):

    def encrypt(self, text: str, key: int) -> str:
        return

    def decrypt(self, ciphertext: str, key: int) -> str:
        return

    def validate_key(self, key: int) -> bool:
        return isinstance(key, int)


class VigenereCipher(Cipher):

    def encrypt(self, text: str, key: str) -> str:
        return

    def decrypt(self, ciphertext: str, key: str) -> str:
        return

    def validate_key(self) -> bool:
        return


class Base64Cipher(Cipher):
    def encrypt(self, text: str, key: Any) -> str:
        return
    def decrypt(self, ciphertext: str, key: Any) -> str:
        return
    def validate_key(self, key: Any) -> bool:
        return key is None
    

class SteganographyCipher(Cipher):
    def encrypt(self, text: str, key: str) -> str:
        return
    def decrypt(self, ciphertext: str, key: str) -> str:
        return
    def validate_key(self, key: str) -> bool:
        return isinstance(key, str)

