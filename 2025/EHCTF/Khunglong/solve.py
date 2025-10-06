from base64 import b64decode
from Crypto.Cipher import AES
import string

def aes(key, iv, encrypted):
    try:
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
        decrypted = cipher.decrypt(b64decode(encrypted))
        return decrypted.decode('utf-8').rstrip('\x00')  # Remove padding
    except Exception as e:
        print("Error during AES decryption:", e)
        return None

def r(text):
    result = []
    for c in text:
        if 'a' <= c <= 'm' or 'A' <= c <= 'M':
            result.append(chr(ord(c) + 13))
        elif 'n' <= c <= 'z' or 'N' <= c <= 'Z':
            result.append(chr(ord(c) - 13))
        else:
            result.append(c)
    return ''.join(result)

def byte_array_to_string(byte_array):
    return ''.join(chr(b) for b in byte_array)

def main():
    key = "PwPCwqR5kTKXDCKLeXr3dHgwtQseobCKciTKYJ4DaJE="  
    iv = "T01_T3n_LAAAAAAA"  
    
    b = [89, 57, 72, 51, 57, 89, 66, 79, 82, 75, 110, 76, 110, 72, 65, 120, 101, 115, 99, 55, 112, 99, 113, 108, 109, 119, 68, 114, 118, 100, 65, 101, 80, 82, 48, 50, 48, 80, 70, 108, 90, 81, 73, 82, 55, 97, 110, 101, 55, 110, 89, 102, 103, 98, 55, 57, 51, 43, 83, 50, 102, 98, 106, 78, 105, 99, 114, 101, 90, 88, 111, 101, 52, 78, 68, 84, 57, 102, 86, 122, 77, 69, 107, 113, 65, 106, 61, 61]
    encrypted_text = byte_array_to_string(b)
    
    decrypted_rot13 = r(encrypted_text)
    decrypted_text = aes(key, iv, decrypted_rot13)
    
    print("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()