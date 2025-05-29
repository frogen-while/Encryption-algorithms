from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
import unittest
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

    def test_save_keys(self):

        key_manager = Cipher.KeyManager()
        private_RSA_key, public_RSA_key = key_manager.generate_RSA_keys("Standard_key")
        private_ECC_key, public_ECC_key = key_manager.generate_ECC_keys("Standard_key")
        

        key_manager.save_keys("Standard_RSA_key", "RSA", private_RSA_key, public_RSA_key)
        key_manager.save_keys("Standard_ECC_key", "ECC", private_ECC_key, public_ECC_key)

        with open("keys_RSA.env", "r") as f:
            keys_RSA = f.read()
        with open("keys_ECC.env", "r") as f:
            keys_ECC = f.read()

        self.assertIn("Standard_RSA_key", keys_RSA)
        self.assertIn("Standard_ECC_key", keys_ECC)
        self.assertIsInstance(keys_RSA["Standard_RSA_key"]["private_key"].encode('utf-8'), rsa.RSAPrivateKeyWithSerialization)
        self.assertIsInstance(keys_RSA["Standard_RSA_key"]["public_key"], rsa.RSAPublicKeyWithSerialization)
        self.assertIsInstance(keys_ECC["Standard_ECC_key"]["private_key"], ec.EllipticCurvePrivateKeyWithSerialization)
        self.assertIsInstance(keys_ECC["Standard_ECC_key"]["public_key"], ec.EllipticCurvePublicKeyWithSerialization)
