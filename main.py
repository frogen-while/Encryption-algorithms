from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization 
import os
from PIL import Image
from typing import Any
import base64

def text_to_bytes(text: str) -> bytes:
    return text.encode('utf-8')

def bytes_to_text(data: bytes) -> str:
    return data.decode('utf-8')

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

    

class KeyManager:
    def generate_RSA_keys(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_ECC_keys(self) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

class CipherRSA(Cipher):
    def encrypt(self, text: str, key: rsa.RSAPublicKey) -> bytes:
        if not self.validate_key(key):
            raise ValueError("Invalid key")
        return key.encrypt(
            text_to_bytes(text),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(self, ciphertext: bytes, key: rsa.RSAPrivateKey) -> str:
        if not self.validate_key(key):
            raise ValueError("Invalid key")
        return bytes_to_text(key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
    
    def validate_key(self, key: Any) -> bool:
        return isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey))


class CipherECC(Cipher):

    def validate_key(self, key: Any) -> bool:
        return isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey))


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



class Base64Cipher(Cipher):
    def encrypt(self, text: str, key: str) -> str:
        return

    def decrypt(self, ciphertext: str, key: str) -> str:
        return 

    def validate_key(self, key: Any) -> bool:
        return isinstance(key, None) 

class SteganographyCipher(Cipher):
    def encrypt(self, text: str, key: str) -> str:
        return
    def decrypt(self, ciphertext: str, key: str) -> str:
        return
    def validate_key(self, key: Any) -> bool:
        return isinstance(key, str) and os.path.exists(key) and key.lower().endswith(('.png', '.jpg', '.jpeg'))
