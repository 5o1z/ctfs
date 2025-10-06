import base64
from Crypto.Cipher import AES
import hashlib

# Giải mã Base64
ciphertext_b64 = "aUcoNnzcerplVJOgso6hf0KOP9w0aQeNlKEXeNSxcx3MkTfLpVXJRcZh1l6wl1zkjSdAYy5p/X/dhEKaH1ClYfHPCiOuIBunTT1sv+VdAlM="
ciphertext = base64.b64decode(ciphertext_b64)

# Tạo khóa từ passphrase
passphrase = "marin kitagawa 256"
key = hashlib.sha256(passphrase.encode()).digest()

# Giải mã bằng AES-256 ECB
cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)

# In kết quả
print("Flag:", plaintext.decode())