from abc import abstractmethod
import cryptography
import os 
import math
import random

with open("config.env", "r") as f:
    config = f.read()


class AbstractCipher:
    @abstractmethod
    def encrypt(self, message):
        raise NotImplementedError("Subclasses must implement this method")

    @abstractmethod
    def decrypt(self, ciphertext):
            raise NotImplementedError("Subclasses must implement this method")

class KeyManager:
    @abstractmethod
    def generate_keys(self):
        raise NotImplementedError("Subclasses must implement this method")
    

class CipherRSA(AbstractCipher, KeyManager):
    def __init__(self, message):
        super().__init__(message)

    def encrypt(self, message):
        return

    def decrypt(self, ciphertext):
        return

    def generate_keys(self):
        return

class CipherECC(AbstractCipher, KeyManager):
    def __init__(self, message):
        super().__init__(message)

    def encrypt(self, message):
        return

    def decrypt(self, ciphertext):
        return

    def generate_keys(self):
        return
    

class CaesarCipher(AbstractCipher):
    def __init__(self, message, shift):
        super().__init__(message)
        self.shift = shift

    def encrypt(self):
        return
    
    def decrypt(self):
        return
    
    def validate_key(self):
        return
    
    
class VigenereCipher(AbstractCipher):
    def __init__(self, message, key):
        super().__init__(message)
        self.key = key

    def encrypt(self):
        return
    def decrypt(self):
        return
    def validate_key(self):
        return
    
    
class Base64Cipher(AbstractCipher):
    def __init__(self, message):
        super().__init__(message)

    def encrypt(self):
        return
    def decrypt(self):
        return
    
class SteganographyCipher(AbstractCipher):
    def __init__(self, message, image_path):
        super().__init__(message)
        self.image_path = image_path

    def encrypt(self):
        return
    def decrypt(self):
        return
    def validate_key(self):
        return
