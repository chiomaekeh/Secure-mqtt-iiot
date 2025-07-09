from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Use a 16-byte (128-bit) key and IV
AES_KEY = b'16byteaeskey1234'  # Replace with your actual key (keep it secret)
AES_IV = b'16byteinitvector'   # Replace with your actual IV

def encrypt_password(plain_text):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_text = pad(plain_text.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted).decode()

def decrypt_password(encrypted_base64):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = base64.b64decode(encrypted_base64)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted.decode()
