import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from generatekey import GenerateKey

class EncryptDecrypt:
    def __init__(self):
        self.secretkey = GenerateKey().generate_key()

    def derive_key(self):
        salt = b'encrypt' # Ideally ,use a secure random salt sand store it securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.secretkey))
        return key

    def encrypt_data(self, data):
        key = self.derive_key()
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        return encrypted_data

    def decrypt_data(self,encrypted_data):
        key = self.derive_key()
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data).decode()
        return decrypted_data


if __name__ == '__main__':
    obj = EncryptDecrypt()
    data = "rajesh"
    enc_data = obj.encrypt_data(data)
    print("Enc data = ",enc_data)
    dec_data = obj.decrypt_data(enc_data)
    print("Dec data = ",dec_data)