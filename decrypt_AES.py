from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def load_derived_key(filename):
    with open(filename, "rb") as file:
        derived_key = file.read()
        return derived_key

def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

    return decrypted_data

def decrypt_message(encrypted_data, derived_key):
    decrypted_chunk = aes_decrypt(encrypted_data, derived_key)
    return decrypted_chunk.decode('latin-1')

def decrypt_photo(encrypted_data, derived_key):
    return aes_decrypt(encrypted_data, derived_key)

def decrypt_and_save_text():
    derived_key = load_derived_key("derived_key.bin")
    with open("encrypted_messages.txt", "rb") as file:
        encrypted_data = file.read()  # Read all data at once
    decrypted_message = decrypt_message(encrypted_data, derived_key)
    print("Decrypted message:", decrypted_message)

def decrypt_and_save_photo():
    derived_key = load_derived_key("derived_key.bin")
    with open("encrypted_photo.bin", "rb") as file:
        encrypted_data = file.read()  # Read all data at once
    decrypted_photo = decrypt_photo(encrypted_data, derived_key)
    
    with open("decrypted_photo.png", "wb") as file:
        file.write(decrypted_photo)
    print("The photo has been decrypted and saved as 'decrypted_photo.png'.")
    
    return "decrypted_photo.png"

def extract_watermark(photo_path):
    with open(photo_path, "rb") as file:
        photo_data = file.read()
    
    start_separator = b"START_WATERMARK::"
    end_separator = b"::END_WATERMARK"

    start_index = photo_data.find(start_separator)
    end_index = photo_data.find(end_separator, start_index)
    
    if start_index == -1 or end_index == -1:
        print("Watermark not found.")
        return None

    watermark_bytes = photo_data[start_index + len(start_separator):end_index]
    watermark = watermark_bytes.decode('utf-8', errors='ignore')
    
    return watermark

if __name__ == "__main__":
    choice = input("What would you like to decrypt? Enter 'text' or 'photo': ").strip().lower()
    
    if choice == 'text':
        decrypt_and_save_text()
    elif choice == 'photo':
        decrypted_photo_path = decrypt_and_save_photo()
        watermark_info = extract_watermark(decrypted_photo_path)
        if watermark_info:
            print("Extracted watermark information:", watermark_info)
    else:
        print("Invalid input. Please enter 'text' or 'photo'.")