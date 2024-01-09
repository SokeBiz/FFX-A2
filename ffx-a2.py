from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

block_size = 16

def FFX_A2_Encrypt(block, key):
    cipher = AES.new(key, AES.MODE_ECB)
    # Pad the block to the block size
    padded_block = pad(block, AES.block_size)
    encrypted_block = cipher.encrypt(padded_block)
    return encrypted_block


def Encrypt_Word(word, key, block_size):
    if len(key) % block_size != 0:
        raise ValueError("Key size must be a multiple of the block size")

    # Add length of the original message as the last byte
    word_len = len(word)
    padded_word = word + bytes([word_len % 256])

    blocks = [padded_word[i:i+block_size] for i in range(0, len(padded_word), block_size)]
    encrypted_blocks = []

    for block in blocks:
        block = FFX_A2_Encrypt(block, key)
        encrypted_blocks.append(block)

    final_encrypted_word = b''.join(encrypted_blocks)
    return final_encrypted_word

def FFX_A2_Decrypt(block, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_block = cipher.decrypt(block)
    return decrypted_block

def Decrypt_Word(ciphertext, key, block_size):
    if len(key) % block_size != 0:
        raise ValueError("Key size must be a multiple of the block size")

    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    decrypted_blocks = []

    for block in blocks:
        decrypted_block = FFX_A2_Decrypt(block, key)
        decrypted_blocks.append(decrypted_block)

    # Extract length of the original message from the last byte
    word_len = decrypted_blocks[-1][-1]

    # Remove padding
    final_decrypted_word = b''.join(decrypted_blocks)[:-word_len]
    return final_decrypted_word


key_size = 16
key = os.urandom(key_size)  # Generate a random key
key = key[:block_size * (len(key) // block_size)]  # Make the key size a multiple of the block size

while True:
    action = input("Enter 'e' to encrypt or 'd' to decrypt: ")

    if action.lower() == 'e':
        plaintext = input("Enter the word to encrypt: ")

        ciphertext = Encrypt_Word(plaintext.encode(), key, block_size)

        print("Key:", key.hex())
        print("Ciphertext:", ciphertext.hex())

    elif action.lower() == 'd':
        ciphertext = input("Enter the ciphertext to decrypt: ")
        ciphertext = bytes.fromhex(ciphertext)
        
        key_hex = input("Enter the key as a hexadecimal string: ")
        key = bytes.fromhex(key_hex)
        
        decrypted_word = Decrypt_Word(ciphertext, key, block_size)
        print("Key:", key.hex())
        print("Decrypted Word:", decrypted_word.decode())

    else:
        print("Invalid action. Please enter 'e' or 'd'.")

    choice = input("Do you want to continue? (y/n) ")
    if choice.lower() != 'y':
        break

print("End")

