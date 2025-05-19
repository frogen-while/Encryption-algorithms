from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization 
import os
from PIL import Image
from typing import Any


class Cipher(ABC):
    @abstractmethod
    def encrypt(self, text: str, key: Any) -> Any:
        raise NotImplementedError("This method should be overridden by subclasses")
    
    @abstractmethod
    def decrypt(self, ciphertext: Any, key: Any) -> str:
        raise NotImplementedError("This method should be overridden by subclasses")
    
    @abstractmethod
    def validate_key(self, key: Any) -> bool:
        raise NotImplementedError("This method should be overridden by subclasses")

class AbstractCipher(Cipher):

    def text_to_bytes(self, text: str) -> bytes:
        return text.encode('utf-8')
    
    def bytes_to_text(self, data: bytes) -> str:
        return data.decode('utf-8')
    

class KeyManager:
    def generate_RSA_keys(self):
        return private_key, public_key
    def generate_ECC_keys(self):
        return private_key, public_key

class CipherRSA(AbstractCipher):

    def encrypt(self, text: str, public_key: rsa.RSAPublicKey) -> bytes:
        return

    def decrypt(self, ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> str:
        return
    
    def validate_key(self, key: Any) -> bool:
        return isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey))


class CipherECC(AbstractCipher):

    def encrypt(self, text: str, public_key: ec.ECPublicKey) -> bytes:
        return

    def decrypt(self, ciphertext: bytes, private_key: ec.ECPrivateKey) -> str:
        return

    def validate_key(self, key: Any) -> bool:
        return isinstance(key, (ec.ECPublicKey, ec.ECPrivateKey))


class CaesarCipher(Cipher):

    def encrypt(self, text: str, key: int) -> str:
        return

    def decrypt(self, ciphertext: str, key: int) -> str:
        return

    def validate_key(self, key: Any) -> bool:
        return isinstance(key, int) and 1 <= key <= 25


class VigenereCipher(Cipher):

    def encrypt(self, text: str, key: str) -> str:
        return

    def decrypt(self, ciphertext: str, key: str) -> str:
        return

    def validate_key(self, key: Any) -> bool:
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        return isinstance(key, str) and key and all(c.lower() in alphabet for c in key)


class Base64Cipher(AbstractCipher):
    def encrypt(self, text: str, key: Any) -> str:
        return
    def decrypt(self, ciphertext: str, key: Any) -> str:
        return
    def validate_key(self, key: Any) -> bool:
        return key is None


class SteganographyCipher(AbstractCipher):
    def encrypt(self, text: str, key: str) -> str:
        return
    def decrypt(self, ciphertext: str, key: str) -> str:
        return
    def validate_key(self, key: Any) -> bool:
        return isinstance(key, str) and os.path.exists(key) and key.lower().endswith(('.png', '.jpg', '.jpeg'))

