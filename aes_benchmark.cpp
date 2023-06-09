#include <chrono>
#include <array>
#include <cstdint>
#include <cassert>
#include "fcryptolib.hpp"

void benchmark(const std::array<uint8_t, 16>& key) {
    std::array<uint8_t, 16> plaintext;
    std::array<uint8_t, 16> outplain;
    std::array<uint8_t, 16> ciphertext;
    std::array<uint8_t, 16> IV;

    // Initialize plaintext and IV with random values
    for (int i = 0; i < 16; ++i) {
        plaintext[i] = rand() % 256;
        IV[i] = rand() % 256;
    }

    const int num_trials = 10000;  // number of trials to average over
    auto start_time = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < num_trials; ++i) {
        AES::encrypt(plaintext, ciphertext,key);
        AES::decrypt(ciphertext,outplain,key);
        assert(plaintext == outplain);
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

    // Calculate bytes encrypted per second
    double bytes_per_second = (16.0 * num_trials) / (duration / 1000.0);

    printf("Test1 result: %f Mbytes/sec\n", bytes_per_second/1024/1024);

    start_time = std::chrono::high_resolution_clock::now();

    std::array<std::array<uint8_t, 16>, 11> roundKey = AES::KeyExpansion(key);
    for (int i = 0; i < num_trials; ++i) {
        AES::encrypt(plaintext, ciphertext,roundKey);
        AES::decrypt(ciphertext,outplain,roundKey);
        assert(plaintext == outplain);
    }

    end_time = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

    // Calculate bytes encrypted per second
    bytes_per_second = (16.0 * num_trials) / (duration / 1000.0);

    printf("Test2 result: %f Mbytes/sec\n", bytes_per_second/1024/1024);
}


int main(void) {
    std::array<uint8_t, 16> key = {0x2b, 0x7e, 0x15, 0x16,
                                   0x28, 0xae, 0xd2, 0xa6,
                                   0xab, 0xf7, 0x15, 0x88,
                                   0x09, 0xcf, 0x4f, 0x3c};

    benchmark(key);

    return 0;
}