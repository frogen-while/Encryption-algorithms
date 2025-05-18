import cryptography
import os 
import math
import random

with open("config.env", "r") as f:
    config = f.read()


class AbstractCipher:

    def __init__(self, message):
        self.message = message
    
    def generate_keys(self):
        raise NotImplementedError("Subclasses must implement this method")

    def validate_key(self, key):
        raise NotImplementedError("Subclasses must implement this method")

    def encrypt(self):
        raise NotImplementedError("Subclasses must implement this method")

    def decrypt(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    def validate_key(self, key):
        raise NotImplementedError("Subclasses must implement this method")

class CipherRSA(AbstractCipher):
    def __init__(self, message):
        super().__init__(message)

    def encrypt(self, message):
        return

    def decrypt(self, ciphertext):
        return
    
    def generate_keys(self):
        return

class CipherECC(AbstractCipher):
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

class StenographyCipher(AbstractCipher):
    def __init__(self, message, image_path):
        super().__init__(message)
        self.image_path = image_path

    def encrypt(self):
        return
    def decrypt(self):
        return
    def validate_key(self):
        return