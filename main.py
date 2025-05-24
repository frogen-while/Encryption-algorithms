from abc import abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from stegano import lsb
import os
from typing import Any, Tuple, Literal, Union
import base64
import json

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

    def save_keys(self, name: str, type: Literal["RSA", "ECC"], private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey], public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]) -> None:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        if type == "RSA":
            try:
                with open("keys_RSA.env", "r") as f:
                    key_data = json.load(f)
                if key_data is None:
                    self.generate_RSA_keys(name = "Standard_key")
            except (FileNotFoundError, json.JSONDecodeError):
                key_data = {}

            key_data.update({
                name: {
                    "type": "RSA",
                    "private_key": private_pem,
                    "public_key": public_pem
                }
            })

            with open("keys_RSA.env", "w", encoding="utf-8") as f:
                json.dump(key_data, f, indent=4)
        elif type == "ECC":
            try:
                with open("keys_ECC.env", "r") as f:
                    key_data = json.load(f)
                if key_data is None:
                    self.generate_ECC_keys(name = "Standard_key")

            except (FileNotFoundError, json.JSONDecodeError):
                key_data = {}

            key_data.update({
                name: {
                    "type": "ECC",
                    "private_key": private_pem,
                    "public_key": public_pem
                }
            })

            with open("keys_ECC.env", "w", encoding="utf-8") as f:
                json.dump(key_data, f, indent=4)
        else:
            raise ValueError("Invalid key type. Use 'RSA' or 'ECC'.")
        
    def generate_RSA_keys(self, name) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return self.save_keys(name, "RSA", private_key, public_key)

    def generate_ECC_keys(self, name) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return self.save_keys(name, "ECC", private_key, public_key)


    def load_keys(self, name: str, type: Literal["RSA", "ECC"]) -> tuple[Any, Any]:
        with open(f"keys_{type}.env", 'r') as f:
            keys = json.load(f)
        if not keys:
            raise ValueError(f"No keys found for {type}")
        if name not in keys:
            raise ValueError(f"No keys found for {name}")
        private_key = serialization.load_pem_private_key(
            keys[name]["private_key"].encode('utf-8'), password=None
        )
        public_key = serialization.load_pem_public_key(
            keys[name]["public_key"].encode('utf-8')
        )
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
        if not self.validate_key(key):
            raise ValueError("Invalid key")

        secret = lsb.hide(key, "Hi there, this is a secret message!")
        secret.save("secret.png")

    def decrypt(self, path_to_secret: str) -> str:
        if not self.validate_key(path_to_secret):
            raise ValueError("Invalid key")
        return lsb.reveal(path_to_secret)

    def validate_key(self, key: Any) -> bool:
        return isinstance(key, str) and os.path.exists(key) and key.lower().endswith(('.png', '.jpg', '.jpeg'))

