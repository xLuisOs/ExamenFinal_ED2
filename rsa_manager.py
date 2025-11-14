import rsa

class RSAManager:
    def __init__(self):
        self.public_key = None
        self.private_key = None
    
    def generate_keys(self, key_size=512):
        self.public_key, self.private_key = rsa.newkeys(key_size)
    
    def sign_message(self, message: str) -> bytes:
        if not self.private_key:
            raise ValueError("No hay clave privada generada")
        
        message_bytes = message.encode('utf-8')
        signature = rsa.sign(message_bytes, self.private_key, "SHA-256")
        return signature
    
    def verify_signature(self, message: str, signature: bytes) -> bool:
        if not self.public_key:
            raise ValueError("No hay clave publica disponible")
        
        message_bytes = message.encode('utf-8')
        
        try:
            rsa.verify(message_bytes, signature, self.public_key)
            return True
        except rsa.VerificationError:
            return False
    
    def get_key_info(self) -> dict:
        if not self.public_key or not self.private_key:
            return {"error": "No hay claves generadas"}
        
        return {
            "public_key_n": self.public_key.n,
            "public_key_e": self.public_key.e,
            "key_size": self.public_key.n.bit_length()
        }