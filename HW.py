import numpy as np

def mod_inverse(det, modulus=26):
    """Finds the modular inverse of det under modulus."""
    for i in range(1, modulus):
        if (det * i) % modulus == 1:
            return i
    raise ValueError("Modular inverse does not exist.")

def encrypt_hill_2x2(plaintext, key):
    """Encrypts a message using the 2x2 Hill cipher."""
    plaintext = plaintext.upper().replace(" ", "")
    if len(plaintext) % 2 != 0:
        plaintext += 'X'  # Padding if necessary
    
    key = np.array(key)
    if key.shape != (2, 2):
        raise ValueError("Key must be a 2x2 matrix.")
    
    plaintext_numbers = [ord(c) - ord('A') for c in plaintext]
    ciphertext = ""
    
    for i in range(0, len(plaintext_numbers), 2):
        pair = np.array(plaintext_numbers[i:i+2])
        encrypted_pair = np.dot(key, pair) % 26
        ciphertext += ''.join(chr(num + ord('A')) for num in encrypted_pair)
    
    return ciphertext

def decrypt_hill_2x2(ciphertext, key):
    """Decrypts a message using the 2x2 Hill cipher."""
    key = np.array(key)
    det = int(np.round(np.linalg.det(key)))
    
    if det == 0 or np.gcd(det, 26) != 1:
        raise ValueError("Key matrix is not invertible under mod 26.")
    
    det_inv = mod_inverse(det, 26)
    adjugate = np.array([[key[1, 1], -key[0, 1]], [-key[1, 0], key[0, 0]]])
    key_inv = (det_inv * adjugate) % 26
    key_inv = key_inv.astype(int)
    
    ciphertext_numbers = [ord(c) - ord('A') for c in ciphertext]
    plaintext = ""
    
    for i in range(0, len(ciphertext_numbers), 2):
        pair = np.array(ciphertext_numbers[i:i+2])
        decrypted_pair = np.dot(key_inv, pair) % 26
        plaintext += ''.join(chr(num + ord('A')) for num in decrypted_pair)
    
    return plaintext

# Example Usage
key = [[3, 3], [2, 5]]  # Example 2x2 key matrix
plaintext = "HELP"
ciphertext = encrypt_hill_2x2(plaintext, key)
decrypted = decrypt_hill_2x2(ciphertext, key)

print(f"Plaintext: {plaintext}")
print(f"Ciphertext: {ciphertext}")
print(f"Decrypted: {decrypted}")
