// g++ -fPIC -c -o python_bind.o python_bind.cpp
// gcc -shared -o aes_lib.so python_bind.o -lstdc++


#include <array>
#include <cstdint>
#include <algorithm>
#include "fcryptolib.hpp"

extern "C" {
    void Encrypt_interface(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key) {
        std::array<uint8_t, 16> plaintext_arr, key_arr, ciphertext_arr;
        std::copy(plaintext, plaintext+16, plaintext_arr.begin());
        std::copy(key, key+16, key_arr.begin());

        AES::encrypt(plaintext_arr, ciphertext_arr, key_arr);

        std::copy(ciphertext_arr.begin(), ciphertext_arr.end(), ciphertext);
    }
}