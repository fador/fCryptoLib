import unittest
import fcryptolib_fador as aes
import numpy as np

class TestAES128(unittest.TestCase):

    def setUp(self):
        self.plaintext = np.array([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34], dtype=np.uint8)
        self.key = np.array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c], dtype=np.uint8)

    def test_encrypt_decrypt(self):
        print('Plaintext:')
        print(self.plaintext)
        print('Key:')
        print(self.key)
        ciphertext = aes.encrypt(self.plaintext, self.key)
        print('Ciphertext:')
        print(ciphertext)
        
        decrypted = aes.decrypt(ciphertext, self.key)
        print('Decrypted:')
        print(decrypted)

        # Check that decrypted message is same as original plaintext
        np.testing.assert_array_equal(decrypted, self.plaintext)


if __name__ == '__main__':
    unittest.main()
