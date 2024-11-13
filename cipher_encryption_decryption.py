import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Caesar Cipher Encryption
def caesar_encrypt(text, shift):
  encrypted_text = ""
  for char in text:
      if char.isalpha():  # Check if the character is a letter
          shift_base = ord('A') if char.isupper() else ord('a')  # Handle uppercase and lowercase separately
          # Shift character and wrap around within alphabet range
          encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
      else:
          encrypted_text += char  # Non-alphabet characters remain unchanged
  return encrypted_text
# Caesar Cipher Decryption
def caesar_decrypt(text, shift):
  return caesar_encrypt(text, -shift)  # Reverse the shift to decrypt

# Monoalphabetic Cipher Encryption
def monoalphabetic_encrypt(text, key_map):
  encrypted_text = ""
  for char in text:
    if char.upper() in key_map:  # Check if character is in key map (case-insensitive)
      new_char = key_map[char.upper()]
      # Preserve original case
      encrypted_text += new_char if char.isupper() else new_char.lower()
    else:
      encrypted_text += char  # Non-alphabet characters remain unchanged
  return encrypted_text
# Monoalphabetic Cipher Decryption
def monoalphabetic_decrypt(text, key_map):
  reverse_key_map = {v: k for k, v in key_map.items()}  # Reverse key map for decryption
  decrypted_text = ""
  for char in text:
    if char.upper() in reverse_key_map:
      new_char = reverse_key_map[char.upper()]
      decrypted_text += new_char if char.isupper() else new_char.lower()
    else:
      decrypted_text += char  # Non-alphabet characters remain unchanged
  return decrypted_text

# Polyalphabetic Cipher Encryption
def vigenere_encrypt(text, keyword):
  encrypted_text = ""
  keyword_repeated = (keyword * ((len(text) // len(keyword)) + 1))[:len(text)]  
  for i in range(len(text)):
    if text[i].isalpha():  # Check if the character is a letter
      shift_base = ord('A') if text[i].isupper() else ord('a')
      shift = ord(keyword_repeated[i].upper()) - ord('A')
      encrypted_text += chr((ord(text[i]) - shift_base + shift) % 26 + shift_base)
    else:
      encrypted_text += text[i]  # Non-alphabet characters remain unchanged
  return encrypted_text
# Polyalphabetic Cipher Decryption
def vigenere_decrypt(text, keyword):
  decrypted_text = ""
  keyword_repeated = (keyword * ((len(text) // len(keyword)) + 1))[:len(text)]  
  for i in range(len(text)):
    if text[i].isalpha():  # Check if the character is a letter
      shift_base = ord('A') if text[i].isupper() else ord('a')
      shift = ord(keyword_repeated[i].upper()) - ord('A')
      decrypted_text += chr((ord(text[i]) - shift_base - shift) % 26 + shift_base)
    else:
      decrypted_text += text[i]  # Non-alphabet characters remain unchanged
  return decrypted_text

# Function to check if the matrix is invertible mod 26
def is_invertible(matrix, mod=26):
  det = int(np.round(np.linalg.det(matrix)))  # Calculate the determinant
  return np.gcd(det, mod) == 1  # Check if gcd(det, 26) is 1 (matrix is invertible)
# Function to get the modular inverse of a matrix
def mod_inverse(matrix, mod):
  det = int(np.round(np.linalg.det(matrix)))  # Calculate determinant of the matrix
  det_inv = pow(det, -1, mod)  # Find modular inverse of the determinant    
  # Find the adjugate (adjoint) of the matrix
  matrix_adj = np.round(det * np.linalg.inv(matrix)).astype(int) % mod    
  # Calculate the inverse matrix by multiplying adjugate by the modular inverse of the determinant
  return (det_inv * matrix_adj) % mod
# Function to convert text into numerical format (A=0, B=1, ..., Z=25)
def text_to_numbers(text):
  return [ord(char) - ord('A') for char in text.upper() if char.isalpha()]
# Function to convert numbers back to text (0=A, 1=B, ..., 25=Z)
def numbers_to_text(numbers):
  return ''.join(chr(num + ord('A')) for num in numbers)

# Hill Cipher Encryption
def hill_encrypt(plaintext, key_matrix):
  if not is_invertible(key_matrix):
    return "Error: Key matrix is not invertible modulo 26."
  plaintext_numbers = text_to_numbers(plaintext)
  # Ensure plaintext length is a multiple of the matrix size
  if len(plaintext_numbers) % len(key_matrix) != 0:
    plaintext_numbers.append(0)  # Add padding if necessary (usually 'A' which is 0)
  # Encrypt in blocks of matrix size
  encrypted_text = []
  for i in range(0, len(plaintext_numbers), len(key_matrix)):
    block = plaintext_numbers[i:i+len(key_matrix)]
    encrypted_block = np.dot(key_matrix, block) % 26
    encrypted_text.extend(encrypted_block)
  return numbers_to_text(encrypted_text)
# Hill Cipher Decryption
def hill_decrypt(ciphertext, key_matrix):
  if not is_invertible(key_matrix):
    return "Error: Key matrix is not invertible modulo 26."
  # Find the inverse of the key matrix
  key_inv = mod_inverse(key_matrix, 26)
  ciphertext_numbers = text_to_numbers(ciphertext)
  # Decrypt in blocks of matrix size
  decrypted_text = []
  for i in range(0, len(ciphertext_numbers), len(key_matrix)):
    block = ciphertext_numbers[i:i+len(key_matrix)]
    decrypted_block = np.dot(key_inv, block) % 26
    decrypted_text.extend(decrypted_block)
  return numbers_to_text(decrypted_text)

# Function to create the Playfair matrix using a keyword
def generate_playfair_matrix(keyword):
  keyword = keyword.upper().replace("J", "I")  # Treat 'J' as 'I'
  seen = set()
  matrix = []
  # Fill matrix with unique characters from the keyword
  for char in keyword:
    if char not in seen and char.isalpha():
      seen.add(char)
      matrix.append(char)
  # Fill remaining characters A-Z (except 'J')
  for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
    if char not in seen:
      matrix.append(char)
  # Convert list to 5x5 matrix
  return [matrix[i:i+5] for i in range(0, 25, 5)]

# Function to find position of a character in the Playfair matrix
def find_position(matrix, char):
  for row in range(5):
    for col in range(5):
      if matrix[row][col] == char:
        return row, col
  return None

# Function to prepare the plaintext or ciphertext for processing (split into pairs)
def prepare_text(text):
  text = text.upper().replace("J", "I")
  prepared_text = ""
  i = 0
  while i < len(text):
    char1 = text[i]
    char2 = text[i + 1] if i + 1 < len(text) else "X"  # Use 'X' as filler
    # If characters are the same or last character is alone, insert 'X'
    if char1 == char2:
      prepared_text += char1 + "X"
      i += 1
    else:
      prepared_text += char1 + char2
      i += 2
  # If odd length, add an 'X' to the end
  if len(prepared_text) % 2 != 0:
    prepared_text += "X"
  return prepared_text

# Playfair Cipher Encryption
def playfair_encrypt(plaintext, matrix):
  plaintext = prepare_text(plaintext)
  ciphertext = ""
  for i in range(0, len(plaintext), 2):
    row1, col1 = find_position(matrix, plaintext[i])
    row2, col2 = find_position(matrix, plaintext[i + 1])
    # Same row: Shift columns to the right
    if row1 == row2:
      ciphertext += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
    # Same column: Shift rows down
    elif col1 == col2:
      ciphertext += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
    # Rectangle rule: Swap columns
    else:
      ciphertext += matrix[row1][col2] + matrix[row2][col1]
  return ciphertext
# Playfair Cipher Decryption
def playfair_decrypt(ciphertext, matrix):
  plaintext = ""
  for i in range(0, len(ciphertext), 2):
    row1, col1 = find_position(matrix, ciphertext[i])
    row2, col2 = find_position(matrix, ciphertext[i + 1])
    # Same row: Shift columns to the left
    if row1 == row2:
      plaintext += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
    # Same column: Shift rows up
    elif col1 == col2:
      plaintext += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
    # Rectangle rule: Swap columns
    else:
      plaintext += matrix[row1][col2] + matrix[row2][col1]
  # Remove padding 'X' added during encryption
  return plaintext.replace("X", "")

# Block Cipher (AES) Encryption
def block_cipher_encrypt(plaintext, key):
    # Initialize cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    # Pad plaintext to be multiple of block size (16 bytes for AES)
    padded_text = pad(plaintext.encode(), AES.block_size)
    # Encrypt and encode in base64 for readability
    encrypted_bytes = cipher.encrypt(padded_text)
    encrypted_text = base64.b64encode(encrypted_bytes).decode()
    return encrypted_text
# Block Cipher (AES) Decryption
def block_cipher_decrypt(encrypted_text, key):
    # Initialize cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    # Decode base64 and decrypt
    encrypted_bytes = base64.b64decode(encrypted_text)
    decrypted_text = unpad(cipher.decrypt(encrypted_bytes), AES.block_size).decode()
    return decrypted_text

def generate_keystream(key, length):
  # RC4 Key Scheduling Algorithm (KSA)
  S = list(range(256))  # State array
  j = 0
  for i in range(256):
    j = (j + S[i] + key[i % len(key)]) % 256
    S[i], S[j] = S[j], S[i]
  # RC4 Pseudo-Random Generation Algorithm (PRGA)
  keystream = []
  i = j = 0
  for _ in range(length):
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    K = S[(S[i] + S[j]) % 256]
    keystream.append(K)
  return keystream
# Stream Cipher (RC4) Encryption
def stream_cipher_encrypt(plaintext, key):
  # Convert key to list of ASCII values
  key = [ord(char) for char in key]
  keystream = generate_keystream(key, len(plaintext))
  encrypted_text = bytes([ord(char) ^ keystream[i] for i, char in enumerate(plaintext)])
  return encrypted_text.hex()  # Convert to hex string
# Stream Cipher (RC4) Decryption
def stream_cipher_decrypt(ciphertext, key):
  # Convert hex string back to bytes
  ciphertext_bytes = bytes.fromhex(ciphertext)
  key = [ord(char) for char in key]
  keystream = generate_keystream(key, len(ciphertext_bytes))
  decrypted_text = ''.join([chr(ciphertext_bytes[i] ^ keystream[i]) for i in range(len(ciphertext_bytes))])
  return decrypted_text

# Main Function
def main():
    print("Cipher Selection:")
    print("1. Caesar Cipher")
    print("2. Monoalphabetic Cipher")
    print("3. Polyalphabetic Cipher")
    print("4. Hill Cipher")
    print("5. Playfair Cipher")
    print("6. Block Cipher (AES)")
    print("7. Stream Cipher (RC4)")
    print("8. Exit Program")
    while True:
      choice = int(input("Enter your choice (1-8): "))
      if choice == 1:
        text = input("Enter text: ")
        shift = int(input("Enter shift value: "))
        test=input("Enter 'E' for encryption and 'D' for decryption: ")
        if test=='e' or test=='E':
          encrypted_text = caesar_encrypt(text, shift)
          print("Encrypted Text:", encrypted_text)
        elif test=='d' or test=='D':
          decrypted_text = caesar_decrypt(text, shift)
          print("Decrypted Text:", decrypted_text)
        else:
          print("Invalid input...")
      elif choice == 2:
        text = input("Enter text: ")
        key_map = {
          'A': 'Q', 'B': 'W', 'C': 'E', 'D': 'R', 'E': 'T', 'F': 'Y', 'G': 'U',
          'H': 'I', 'I': 'O', 'J': 'P', 'K': 'A', 'L': 'S', 'M': 'D', 'N': 'F',
          'O': 'G', 'P': 'H', 'Q': 'J', 'R': 'K', 'S': 'L', 'T': 'Z', 'U': 'X',
          'V': 'C', 'W': 'V', 'X': 'B', 'Y': 'N', 'Z': 'M'
        }
        test=input("Enter 'E' for encryption and 'D' for decryption: ")
        if test=='e' or test=='E':
          encrypted_text = monoalphabetic_encrypt(text, key_map)
          print("Encrypted Text:", encrypted_text)
        elif test=='d' or test=='D':
          decrypted_text = monoalphabetic_decrypt(text, key_map)
          print("Decrypted Text:", decrypted_text)
        else:
          print("Invalid input...")
      elif choice == 3:
        text = input("Enter text: ")
        keyword = input("Enter keyword: ")
        test=input("Enter 'E' for encryption and 'D' for decryption: ")
        if test=='e' or test=='E':
          encrypted_text = vigenere_encrypt(text, keyword)
          print("Encrypted Text:", encrypted_text)
        elif test=='d' or test=='D':
          decrypted_text = vigenere_decrypt(text, keyword)
          print("Decrypted Text:", decrypted_text)
        else:
          print("Invalid input...")
      elif choice == 4:
        # 2x2 key matrix for Hill Cipher (Ensure the matrix is invertible modulo 26)
        key_matrix = np.array([[3, 3], [2, 5]])  # A valid invertible matrix modulo 26
        # Check if the matrix is invertible
        if not is_invertible(key_matrix):
          print("Error: Key matrix is not invertible modulo 26.")
          return
        text = input("Enter text (only uppercase alphabets): ").upper()
        test=input("Enter 'E' for encryption and 'D' for decryption: ")
        if test=='e' or test=='E':
          encrypted_text = hill_encrypt(text, key_matrix)
          print("Encrypted Text:", encrypted_text)
        elif test=='d' or test=='D':
          decrypted_text = hill_decrypt(text, key_matrix)
          print("Decrypted Text:", decrypted_text)
        else:
          print("Invalid input...")
      elif choice == 5:
        keyword = input("Enter keyword for Playfair Cipher: ")
        matrix = generate_playfair_matrix(keyword)
        # Print matrix for reference
        print("\nPlayfair Matrix:")
        for row in matrix:
          print(" ".join(row))
        text = input("Enter text: ")
        test=input("Enter 'E' for encryption and 'D' for decryption: ")
        if test=='e' or test=='E':
          encrypted_text = playfair_encrypt(text, matrix)
          print("Encrypted Text:", encrypted_text)
        elif test=='d' or test=='D':
          decrypted_text = playfair_decrypt(text, matrix)
          print("Decrypted Text:", decrypted_text)
        else:
          print("Invalid input...")
      elif choice == 6:
        text = input("Enter text: ")
        key = input("Enter a 16-character key: ").encode()  # AES-128 requires a 16-byte key
        if len(key) != 16:
          print("Error: Key must be 16 characters long!")
          return
        test=input("Enter 'E' for encryption and 'D' for decryption: ")
        if test=='e' or test=='E':
          encrypted_text = block_cipher_encrypt(text, key)
          print("Encrypted Text:", encrypted_text)
        elif test=='d' or test=='D':
          decrypted_text = block_cipher_decrypt(text, key)
          print("Decrypted Text:", decrypted_text)
        else:
          print("Invalid input...")
      elif choice == 7:
        text = input("Enter text: ")
        key = input("Enter the encryption key: ")
        test=input("Enter 'E' for encryption and 'D' for decryption: ")
        if test=='e' or test=='E':
          encrypted_text = stream_cipher_encrypt(text, key)
          print("Encrypted Text:", encrypted_text)  # Now a hex string
        elif test=='d' or test=='D':
          decrypted_text = stream_cipher_decrypt(text, key)
          print("Decrypted Text:", decrypted_text)
        else:
          print("Invalid input...")
      elif choice==8:
        break
      else:
          print("Invalid choice!")

if __name__ == "__main__":
    main()