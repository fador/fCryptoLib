import ctypes

# Load the shared library
aes_lib = ctypes.CDLL('./aes_lib.so')

# Set up the argument types for Encrypt_CBC_interface
aes_lib.Encrypt_interface.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),  # plaintext
    ctypes.POINTER(ctypes.c_uint8),  # key
    ctypes.POINTER(ctypes.c_uint8)  # ciphertext
]

# Set up the return type
aes_lib.Encrypt_interface.restype = None

# Create ctypes arrays for the plaintext, key, ciphertext, and IV
plaintext = (ctypes.c_uint8 * 16)()
key = (ctypes.c_uint8 * 16)()
ciphertext = (ctypes.c_uint8 * 16)()

# Fill in your plaintext, key, and IV
plaintext[:] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
key[:] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]

# Call the function
aes_lib.Encrypt_interface(plaintext, ciphertext, key)

hexstring = ''.join('%02X ' % b for b in plaintext)
print('Original text:   '+hexstring)

hexstring = ''.join('%02X ' % b for b in ciphertext)
# hexstring now contains the encrypted text
print('Encrypted text:  '+hexstring)
