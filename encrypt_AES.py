from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import shlex
import os

# TreeKEM
class TreeNode:
    def __init__(self):
        self.children = []
        self.group_key = None

    def add_member_TreeNode(self, new_public_key):
        new_node = TreeNode()
        new_node.public_key = new_public_key
        self.children.append(new_node)
        self.update_key_TreeNode()

    def remove_member_TreeNode(self, public_key_to_remove):
        for child in self.children:
            if child.public_key == public_key_to_remove:
                self.children.remove(child)
                self.update_key_TreeNode()
                break

    def update_key_TreeNode(self):
        self.group_key = self.generate_group_key_TreeNode()

    def generate_group_key_TreeNode(self):
        if not self.children:
            return os.urandom(32)
        
        combined_key = b''.join(child.generate_group_key_TreeNode() for child in self.children)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=b'',
        ).derive(combined_key)

    def print_tree(self, level=0):
        if not self.children:
            print("  " * level + f"Leaf Node Level {level}: Public Key: {self.public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()}")
        else:
            print("  " * level + f"Node Level {level}: Group Key: {self.group_key.hex()}")
        
        for child in self.children:
            child.print_tree(level + 1)

# AES Functions
def aes_encrypt(data, key):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted  # Prepend IV to the encrypted data

def encrypt_long_message(message, derived_key):
    encrypted_chunks = []
    message_bytes = message.encode()

    encrypted_message = aes_encrypt(message_bytes, derived_key)
    encrypted_chunks.append(encrypted_message)

    return encrypted_chunks

def encrypt_photo(photo_path, derived_key):
    with open(photo_path, "rb") as photo_file:
        photo_data = photo_file.read()

    encrypted_chunks = []
    
    encrypted_photo = aes_encrypt(photo_data, derived_key)
    encrypted_chunks.append(encrypted_photo)

    return encrypted_chunks

def encrypt_photo_with_watermark(photo_path, derived_key, sender_id, receiver_id):
    with open(photo_path, "rb") as photo_file:
        photo_data = photo_file.read()
    
    watermark = f"{sender_id}:{receiver_id}".encode()
    photo_data_with_watermark = photo_data + b"START_WATERMARK::" + watermark + b"::END_WATERMARK"

    encrypted_chunks = []
    
    encrypted_photo = aes_encrypt(photo_data_with_watermark, derived_key)
    encrypted_chunks.append(encrypted_photo)

    return encrypted_chunks

def save_derived_key(derived_key, filename):
    with open(filename, "wb") as file:
        file.write(derived_key)

def encrypt_and_save_text(root, message):
    derived_key = root.group_key
    
    encrypted_chunks = encrypt_long_message(message, derived_key)

    save_derived_key(derived_key, "derived_key.bin")

    with open("encrypted_messages.txt", "wb") as file:
        for encrypted_chunk in encrypted_chunks:
            file.write(encrypted_chunk)
    
    print("Encrypted Message chunks:")
    for i, encrypted_chunk in enumerate(encrypted_chunks):
        print(f"Chunk {i + 1}: {encrypted_chunk}")

def encrypt_and_save_photo(root, photo_path, sender_id=None, receiver_id=None, add_watermark=False):
    derived_key = root.group_key
    
    if add_watermark:
        encrypted_chunks = encrypt_photo_with_watermark(photo_path, derived_key, sender_id, receiver_id)
    else:
        encrypted_chunks = encrypt_photo(photo_path, derived_key)

    save_derived_key(derived_key, "derived_key.bin")

    with open("encrypted_photo.bin", "wb") as file:
        for encrypted_chunk in encrypted_chunks:
            file.write(encrypted_chunk)
    
    print("The encrypted photo has been saved to 'encrypted_photo.bin'.")

# Main
if __name__ == "__main__":
    root = TreeNode()
    
    choice = input("What would you like to encrypt? Enter 'text' or 'photo': ").strip().lower()
    num_members = int(input("Number of members in the group: "))

    for _ in range(num_members):
        new_private_key = x25519.X25519PrivateKey.generate()
        new_public_key = new_private_key.public_key()
        root.add_member_TreeNode(new_public_key)

    root.update_key_TreeNode()

    if choice == 'text':
        message = input("Please enter the text message you want to encrypt: ")
        encrypt_and_save_text(root, message)
    elif choice == 'photo':
        photo_path_input = input("Please enter the path of the photo you want to encrypt: ")
        photo_path = shlex.split(photo_path_input)[0]
        
        add_watermark = input("Would you like to add a watermark? (yes/no): ").strip().lower()
        
        if add_watermark == 'yes':
            sender_id = input("Please enter the sender's identity: ")
            receiver_id = input("Please enter the receiver's identity: ")
            encrypt_and_save_photo(root, photo_path, sender_id, receiver_id, add_watermark=True)
            watermark_info = (sender_id, receiver_id)  # Save watermark info for later use
        else:
            encrypt_and_save_photo(root, photo_path, add_watermark=False)
            watermark_info = None  # No watermark to retain
    else:
        print("Invalid input. Please enter 'text' or 'photo'.")
        exit()

    root.print_tree()

    action = input("Would you like to add or remove members? (add/remove/no): ")
    if action == "add":
        new_private_key = x25519.X25519PrivateKey.generate()
        new_public_key = new_private_key.public_key()
        root.add_member_TreeNode(new_public_key)
        print("New member added.")

        root.update_key_TreeNode()
        
        # Re-encrypt the photo with watermark if applicable
        if choice == 'photo' and watermark_info:
            sender_id, receiver_id = watermark_info
            encrypt_and_save_photo(root, photo_path, sender_id, receiver_id, add_watermark=True)
        elif choice == 'text':
            encrypt_and_save_text(root, message)
        
        root.print_tree()
    
    elif action == "remove":
        index_to_remove = int(input("Enter the index of the member to remove (starting from 0): "))
        if 0 <= index_to_remove < len(root.children):
            root.remove_member_TreeNode(root.children[index_to_remove].public_key)
            print("Member removed.")

            root.update_key_TreeNode()
            
            # Re-encrypt the photo with watermark if applicable
            if choice == 'photo' and watermark_info:
                sender_id, receiver_id = watermark_info
                encrypt_and_save_photo(root, photo_path, sender_id, receiver_id, add_watermark=True)
            elif choice == 'text':
                encrypt_and_save_text(root, message)
            
            root.print_tree()
        else:
            print("Invalid index.")

    elif action == "no":
        print("No changes were made to the members.")
    else:
        print("Invalid input. Please enter 'add', 'remove', or 'no'.")