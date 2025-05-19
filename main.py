from abc import abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from steganocryptopy.steganography import Steganography as stego
import os
from typing import Any
import base64

def text_to_bytes(text: str) -> bytes:
    return text.encode('utf-8')

def bytes_to_text(data: bytes) -> str:
    return data.decode('utf-8')

def text_to_number(text: str) -> list[int]:
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        cleaned_text = [c.lower() for c in text if c.lower() in alphabet]
        return [alphabet.index(c) for c in cleaned_text]

class Cipher:
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
        result = ""
        if self.validate_key(key):

            for char in text:
                if char.isalpha():
                    shift = (ord(char.lower()) - ord('a') + key) % 26
                    new_char = chr(shift + ord('a'))
                    result += new_char.upper() if char.isupper() else new_char
                else:
                    result += char
            return result
        else:
            raise ValueError("Invalid key")
    def decrypt(self, ciphertext: str, key: int) -> str:
        if not self.validate_key(key):
            raise ValueError("Invalid key")
        result = ""
        for char in ciphertext:
            if char.isalpha():
                shift = (ord(char.lower()) - ord('a') - key) % 26
                new_char = chr(shift + ord('a'))
                result += new_char.upper() if char.isupper() else new_char
            else:
                result += char
        return result if self.validate_key(key) else ValueError("Invalid key")

    def validate_key(self, key: Any) -> bool:
        return isinstance(key, int) and 1 <= key <= 25


class VigenereCipher(Cipher):
    def __init__(self):
        self.alphabet = "abcdefghijklmnopqrstuvwxyz"

    def encrypt(self, text: str, key: str) -> str:

        text_numbers = text_to_number(text)
        key_numbers = text_to_number(key)

        key_repeated = key_numbers * (len(text_numbers) // len(key_numbers) + 1)
        for i in range(len(key_repeated)):
            key_repeated[i] = f"{key_repeated[i]}"
        temp = key_repeated[:len(text_numbers)]
        key_repeated = []
        for i in range(len(temp)):
            temp[i] = int(temp[i])
            key_repeated.append(temp[i])
        key_repeated = key_repeated[:len(text_numbers)]

        shifted = [(t + k) % 26 for t, k in zip(text_numbers, key_repeated)]
        result = ""
        num_idx = 0
        for char in text.lower():
            if char in self.alphabet:
                result += self.alphabet[shifted[num_idx]]
                num_idx += 1
            else:
                result += char
        return result

    def decrypt(self, ciphertext: str, key: str) -> str:
        text_numbers = text_to_number(ciphertext)
        key_numbers = text_to_number(key)


        key_repeated = key_numbers * (len(text_numbers) // len(key_numbers) + 1)
        for i in range(len(key_repeated)):
            key_repeated[i] = f"{key_repeated[i]}"
        temp = key_repeated[:len(text_numbers)]
        key_repeated = []
        for i in range(len(temp)):
            temp[i] = int(temp[i])
            key_repeated.append(temp[i])
        key_repeated = key_repeated[:len(text_numbers)]
        

        shifted = [(t - k) % 26 for t, k in zip(text_numbers, key_repeated)]
        result = ""
        num_idx = 0
        for char in ciphertext.lower():
            if char in self.alphabet:
                result += self.alphabet[shifted[num_idx]]
                num_idx += 1
            else:
                result += char
        return result

    def validate_key(self, key: Any) -> bool:
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        return isinstance(key, str) and key and all(c.lower() in alphabet for c in key)



class Base64Cipher(Cipher):
    def encrypt(self, text: str, key: str) -> str:
        bytes = text_to_bytes(text)
        return base64.b64encode(bytes).decode('utf-8')

    def decrypt(self, ciphertext: str, key: str) -> str:
        bytes_data = base64.b64decode(ciphertext)
        return bytes_to_text(bytes_data)

    def validate_key(self, key: Any) -> bool:
        return key is None

class SteganographyCipher(Cipher):
    def encrypt(self, key: str) -> str:
        stego.generate_key("secret_key")
        secret = stego.encrypt("secret_key", key, "massage.txt")
        secret.save("secret.png")

    def decrypt(self, path_to_secret: str, key: str) -> str:
        # if not self.validate_key(path_to_secret):
        #     raise ValueError("Invalid key")
        
        return stego.decrypt("secret_key", path_to_secret)

    # def validate_key(self, key: Any) -> bool:
    #     return isinstance(key, str) and os.path.exists(key) and key.lower().endswith(('.png', '.jpg', '.jpeg'))

