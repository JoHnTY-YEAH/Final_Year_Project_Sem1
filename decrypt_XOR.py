from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

def load_derived_key(filename):
    with open(filename, "rb") as file:
        derived_key = file.read()
        return derived_key

def decrypt_message(encrypted_chunks, derived_key):
    decrypted_message = b""
    for encrypted_chunk in encrypted_chunks:
        decrypted_chunk = bytes([char ^ derived_key[i % 32] for i, char in enumerate(encrypted_chunk)])
        decrypted_message += decrypted_chunk
    decrypted_message_text = decrypted_message.decode('latin-1')
    return decrypted_message_text

def decrypt_photo(encrypted_chunks, derived_key):
    decrypted_photo = b""
    for encrypted_chunk in encrypted_chunks:
        decrypted_chunk = bytes([char ^ derived_key[i % 32] for i, char in enumerate(encrypted_chunk)])
        decrypted_photo += decrypted_chunk
    return decrypted_photo

def decrypt_and_save_text():
    derived_key = load_derived_key("derived_key.bin")
    with open("encrypted_messages.txt", "rb") as file:
        encrypted_chunks = []
        while chunk := file.read(32):
            encrypted_chunks.append(chunk)
    decrypted_message = decrypt_message(encrypted_chunks, derived_key)
    print("Decrypted message:", decrypted_message)

def decrypt_and_save_photo():
    derived_key = load_derived_key("derived_key.bin")
    with open("encrypted_photo.bin", "rb") as file:
        encrypted_chunks = []
        while chunk := file.read(32):
            encrypted_chunks.append(chunk)
    decrypted_photo = decrypt_photo(encrypted_chunks, derived_key)
    
    # Save the decrypted photo
    with open("decrypted_photo.png", "wb") as file:
        file.write(decrypted_photo)
    print("The photo has been decrypted and saved as 'decrypted_photo.png'.")
    
    return "decrypted_photo.png"  # Return the path of the decrypted photo

def extract_watermark(photo_path):
    with open(photo_path, "rb") as file:
        photo_data = file.read()
    
    # Find the position of the separator
    start_separator = b"START_WATERMARK::"
    end_separator = b"::END_WATERMARK"

    start_index = photo_data.find(start_separator)
    end_index = photo_data.find(end_separator, start_index)  # Search for the separator from the end
    
    if start_index == -1 or end_index == -1:
        print("Watermark not found.")
        return None

    # Extract watermark information
    watermark_bytes = photo_data[start_index + len(start_separator):end_index]
    watermark = watermark_bytes.decode('utf-8', errors='ignore')  # Decode watermark information
    
    return watermark

if __name__ == "__main__":
    choice = input("What would you like to decrypt? Enter 'text' or 'photo': ").strip().lower()
    
    if choice == 'text':
        decrypt_and_save_text()
    elif choice == 'photo':
        # First decrypt the photo
        decrypted_photo_path = decrypt_and_save_photo()
        # Then extract the watermark
        watermark_info = extract_watermark(decrypted_photo_path)
        if watermark_info:
            print("Extracted watermark information:", watermark_info)
    else:
        print("Invalid input. Please enter 'text' or 'photo'.")