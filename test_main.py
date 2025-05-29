from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
import unittest
import os
import main as Cipher

ciphers_classes = [Cipher.VigenereCipher, Cipher.CaesarCipher, Cipher.CipherRSA, Cipher.CipherECC, Cipher.Base64Cipher, Cipher.SteganographyCipher]

class TestKeyManager(unittest.TestCase):
    def test_key_generation(self):
        private_RSA_key, public_RSA_key = Cipher.KeyManager().generate_RSA_keys("Standard_key")
        private_ECC_key, public_ECC_key = Cipher.KeyManager().generate_ECC_keys("Standard_key")

        self.assertIsInstance(private_RSA_key, rsa.RSAPrivateKey)
        self.assertIsInstance(public_RSA_key, rsa.RSAPublicKey)
        self.assertIsInstance(private_ECC_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(public_ECC_key, ec.EllipticCurvePublicKey)

    def test_save_and_load_keys(self):

        key_manager = Cipher.KeyManager()
        private_RSA_key, public_RSA_key = key_manager.generate_RSA_keys("Standard_key")
        private_ECC_key, public_ECC_key = key_manager.generate_ECC_keys("Standard_key")
        

        key_manager.save_keys("Standard_RSA_key", "RSA", private_RSA_key, public_RSA_key)
        key_manager.save_keys("Standard_ECC_key", "ECC", private_ECC_key, public_ECC_key)

        private_RSA_key, public_RSA_key = key_manager.load_keys("Standard_RSA_key", "RSA")
        private_ECC_key, public_ECC_key = key_manager.load_keys("Standard_ECC_key", "ECC")

        with open("keys_RSA.env", "r") as f:
            keys_RSA = f.read()
        with open("keys_ECC.env", "r") as f:
            keys_ECC = f.read()

        self.assertIn("Standard_RSA_key", keys_RSA)
        self.assertIn("Standard_ECC_key", keys_ECC)
        self.assertIsInstance(private_RSA_key, rsa.RSAPrivateKeyWithSerialization)
        self.assertIsInstance(public_RSA_key, rsa.RSAPublicKeyWithSerialization)
        self.assertIsInstance(private_ECC_key, ec.EllipticCurvePrivateKeyWithSerialization)
        self.assertIsInstance(public_ECC_key, ec.EllipticCurvePublicKeyWithSerialization)
class TestCiphers(unittest.TestCase):

    def test_cipher_RSA(self):
        key_manager = Cipher.KeyManager()
        cipher_RSA = Cipher.CipherRSA()
        cipher_ECC = Cipher.CipherECC()
        cipher_Caesar = Cipher.CaesarCipher()
        cipher_Vigenere = Cipher.VigenereCipher()
        cipher_Base64 = Cipher.Base64Cipher()
        cipher_Steganography = Cipher.SteganographyCipher()
        with open("tests/data/message_100.txt", "r") as f:
            message = f.read()
        # Test RSA
        private_key, public_key = key_manager.load_keys("Standard_RSA_key", "RSA")
        encrypted_message = cipher_RSA.encrypt(message, public_key)
        self.assertNotEqual(encrypted_message, message)
        self.assertEqual(cipher_RSA.decrypt(encrypted_message, private_key), message)

        private_key, public_key = key_manager.load_keys("Standard_ECC_key", "ECC")

        # Test ECC
        encrypted_message = cipher_ECC.encrypt(message, public_key)
        self.assertNotEqual(encrypted_message, message)
        self.assertEqual(cipher_ECC.decrypt(encrypted_message, private_key), message)
        for i in range(1,11,9):
            for j in range(100,600,200):
                with open(f"tests/data/message_{i*j}.txt", "r") as f:
                    message = f.read()
                # Test Caesar Cipher
                encrypted_message = cipher_Caesar.encrypt(message, 3)
                self.assertNotEqual(encrypted_message, message)
                self.assertEqual(cipher_Caesar.decrypt(encrypted_message, 3), message)
                # Test Vigenere Cipher
                encrypted_message = cipher_Vigenere.encrypt(message, "testkey")
                self.assertNotEqual(encrypted_message, message)             
                self.assertEqual(cipher_Vigenere.decrypt(encrypted_message, "testkey"), message.lower())    
                # Test Base64 Cipher
                encrypted_message = cipher_Base64.encrypt(message, None)
                self.assertNotEqual(encrypted_message, message)  
                self.assertEqual(cipher_Base64.decrypt(encrypted_message, None), message)
                # Test Steganography Cipher
                encrypted_message = cipher_Steganography.encrypt(message, "tests/data/image.jpeg")
                self.assertIsInstance(os.path.exists(encrypted_message))
                decrypted_message = cipher_Steganography.decrypt(encrypted_message, "tests/data/image.jpeg")
                self.assertEqual(decrypted_message, message)
                self.assertTrue(os.path.exists(decrypted_message))
