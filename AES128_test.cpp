#include <fstream>
#include "fcryptolib.hpp"

int main() {
    std::array<uint8_t, 16> plaintext = //{0x00, 0x11, 0x22, 0x33, 0x44, 0x55,0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,0xcc, 0xdd, 0xee, 0xff};
     {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    std::array<uint8_t, 16> key = //{0x00, 0x01, 0x02, 0x03, 0x04, 0x05,0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,0x0c, 0x0d, 0x0e, 0x0f};
     {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
                                  
    std::array<uint8_t, 16> ciphertext;
    std::array<uint8_t, 16> decryptedtext;

    // Encrypt plaintext
    AES::encrypt(plaintext, ciphertext, key);

    // Decrypt ciphertext
    AES::decrypt(ciphertext, decryptedtext, key);

    // Print original, encrypted, and decrypted texts
    std::cout << "Original text:   ";
    for (const auto &byte : plaintext) {
        printf("%02x ", byte);
    }
    std::cout << std::endl;

    std::cout << "Encrypted text:  ";
    for (const auto &byte : ciphertext) {
        printf("%02x ", byte);
    }
    std::cout << std::endl;

    std::cout << "Decrypted text:  ";
    for (const auto &byte : decryptedtext) {
        printf("%02x ", byte);
    }
    std::cout << std::endl;

        // Write plaintext to file
    std::ofstream plaintext_file("plaintext.txt", std::ios::binary);
    plaintext_file.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());

    // Write encrypted text to file
    std::ofstream ciphertext_file("ciphertext.txt", std::ios::binary);
    ciphertext_file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());


    return 0;
}
