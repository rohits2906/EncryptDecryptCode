from cryptography.fernet import Fernet

class GenerateKey:
    def __init__(self):
        pass

    def generate_key(self):
        key = Fernet.generate_key()
        return key