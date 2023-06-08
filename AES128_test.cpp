#include <iostream>
#include <array>
#include <cstdint>

class AES {
public:
    AES() = delete; // No default constructor (AES is a namespace)
    ~AES() = delete;

    static void encrypt(const std::array<uint8_t, 16>& plaintext, std::array<uint8_t, 16>& ciphertext, const std::array<uint8_t, 16>& cipherKey) {
        std::array<uint8_t, 16> state = plaintext;

        // Generate round keys
        std::array<std::array<uint8_t, 16>, 11> roundKeys = KeyExpansion(cipherKey);

        for(auto key: roundKeys) {
            for(auto byte: key) {
                printf("%02x ", (int)byte);
            }
            std::cout << std::endl;
        }

        encrypt(plaintext, ciphertext, roundKeys);
    }

    static void encrypt(const std::array<uint8_t, 16>& plaintext, std::array<uint8_t, 16>& ciphertext, std::array<std::array<uint8_t, 16>, 11>& roundKeys) {
        std::array<uint8_t, 16> state = plaintext;

        // Initial AddRoundKey step
        AddRoundKey(state, roundKeys[0]);

        // 9 rounds of SubBytes, ShiftRows, MixColumns, and AddRoundKey
        for (int round = 1; round <= 9; ++round) {
            /*SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, roundKeys[round]);
            */
            SubBytes(state);
            ShiftRows(state);            
            MixColumns(state);
            AddRoundKey(state, roundKeys[round]);
        }

        // Final round (no MixColumns)
        SubBytes(state);
        ShiftRows(state);        
        AddRoundKey(state, roundKeys[10]);

        ciphertext = state;
    }


    static void decrypt(const std::array<uint8_t, 16>& ciphertext, std::array<uint8_t, 16>& plaintext, const std::array<uint8_t, 16>& cipherKey) {
        std::array<uint8_t, 16> state = ciphertext;

        // Generate round keys
        std::array<std::array<uint8_t, 16>, 11> roundKeys = KeyExpansion(cipherKey);

        decrypt(ciphertext, plaintext, roundKeys);
    }

    static void decrypt(const std::array<uint8_t, 16>& ciphertext, std::array<uint8_t, 16>& plaintext, std::array<std::array<uint8_t, 16>, 11>& roundKeys) {
        std::array<uint8_t, 16> state = ciphertext;

        // AddRoundKey with the last round key
        AddRoundKey(state, roundKeys[10]);

        // 9 rounds of InvShiftRows, InvSubBytes, AddRoundKey, and InvMixColumns
        for (int round = 9; round >= 1; --round) {
            InvShiftRows(state);
            InvSubBytes(state);            
            AddRoundKey(state, roundKeys[round]);            
            InvMixColumns(state);
        }

        // Last round (no InvMixColumns)
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys[0]);

        plaintext = state;
    }

    static void Encrypt_CBC(const std::array<uint8_t, 16>& plaintext, const std::array<uint8_t, 16>& key, 
                std::array<uint8_t, 16>& ciphertext, const std::array<uint8_t, 16>& IV) {
        // XOR plaintext with IV
        std::array<uint8_t, 16> xor_output;
        for(int i=0; i<16; ++i){
            xor_output[i] = plaintext[i] ^ IV[i];
        }
        // AES-128 encryption
        encrypt(xor_output, ciphertext, key);
    }

    static void Decrypt_CBC(const std::array<uint8_t, 16>& ciphertext, const std::array<uint8_t, 16>& key, 
                    std::array<uint8_t, 16>& plaintext, const std::array<uint8_t, 16>& IV) {
        // AES-128 decryption
        std::array<uint8_t, 16> intermediate;
        decrypt(ciphertext, intermediate, key);

        // XOR with IV
        for(int i=0; i<16; ++i){
            plaintext[i] = intermediate[i] ^ IV[i];
        }
    }



    /* This function multiplies two elements of GF(2^8) together.
     * The GF(2^8) field is defined by the polynomial x^8 + x^4 + x^3 + x + 1.
     * If the result of the multiplication exceeds 8 bits, then it is reduced modulo
     * the irreducible polynomial defined above.
     */
    /*
    static std::array<std::array<uint8_t, 16>, 11> KeyExpansion(const std::array<uint8_t, 16>& cipherKey) {
        std::array<std::array<uint8_t, 16>, 11> roundKeys;
        roundKeys[0] = cipherKey;

        for (int i = 1; i <= 10; ++i) {
            std::array<uint8_t, 4> temp = {roundKeys[i-1][13], roundKeys[i-1][14], roundKeys[i-1][15], roundKeys[i-1][12]};
            temp = SubWord(RotWord(temp));
            for (int j = 0; j < 4; ++j) {
                temp[j] ^= AES::Rcon[i];
                roundKeys[i][j] = roundKeys[i-1][j] ^ temp[j];
            }
            for (int j = 4; j < 16; ++j) {
                roundKeys[i][j] = roundKeys[i-1][j] ^ roundKeys[i][j-4];
            }
        }
        return roundKeys;
    }*/

    static std::array<std::array<uint8_t, 16>, 11> KeyExpansion(const std::array<uint8_t, 16>& cipherKey) {
        std::array<std::array<uint8_t, 16>, 11> roundKeys;
        roundKeys[0] = cipherKey;

        uint32_t w[44];
        for(int i = 0; i<44; ++i) {
            w[i] = (roundKeys[i/4][(i%4)*4] << 24) | (roundKeys[i/4][(i%4)*4+1] << 16) | (roundKeys[i/4][(i%4)*4+2] << 8) | (roundKeys[i/4][(i%4)*4+3]);
        }

        for(int i = 4; i<44; ++i) {
            uint32_t temp = w[i-1];
            
            if(i%4 == 0) {
                temp = SubWord(RotWord(temp));
                temp = temp ^ (Rcon[i/4]);
            }
            
            w[i] = w[i-4] ^ temp;            
        }
        
        for(int i = 0; i<44; ++i) {
            roundKeys[i/4][(i%4)*4] = w[i] >> 24;
            roundKeys[i/4][(i%4)*4+1] = w[i] >> 16;
            roundKeys[i/4][(i%4)*4+2] = w[i] >> 8;
            roundKeys[i/4][(i%4)*4+3] = w[i];
        }
        
        return roundKeys;
    }
/*
    void KeyExpansion(uint8_t* inputKey, uint32_t* expandedKey) {
        int i;
        uint32_t temp;
        const int Nk = 4;
        const int Nb = 4;
        const int Nr = 10;

        // The first round key is the key itself.
        for (i = 0; i < Nk; ++i)
        {
            expandedKey[i] = (inputKey[4 * i] << 24) | (inputKey[4 * i + 1] << 16) | (inputKey[4 * i + 2] << 8) | (inputKey[4 * i + 3]);
        }

        // All other round keys are found from the previous round keys.
        for (; i < Nb * (Nr + 1); ++i)
        {
            temp = expandedKey[i - 1];
            if (i % Nk == 0)
            {
                // This function rotates the 4 bytes in a word to the left once.
                // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
                temp = (temp << 8) | (temp >> 24);

                // SubWord() is a function that takes a four-byte input word and 
                // applies the S-box to each of the four bytes to produce an output word.
                temp = SubWord(temp);

                temp ^= Rcon[i/Nk];
            }
            expandedKey[i] = expandedKey[i - Nk] ^ temp;
        }
    }
*/
/*
    static std::array<std::array<uint8_t, 16>, 11> KeyExpansion(const std::array<uint8_t, 16>& cipherKey) {
        std::array<std::array<uint8_t, 16>, 11> expandedKeys;
        std::array<uint8_t, 4> temp;

        // The first round key is the key itself.
        expandedKeys[0] = cipherKey;

        // All other round keys are found from the previous round keys.
        for (int i = 1; i <= 10; ++i) {
            temp = expandedKeys[i-1];
            // This function rotates the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
            std::rotate(temp.begin(), temp.begin()+1, temp.end());

            // SubWord() is a function that takes a four-byte input word and 
            // applies the S-box to each of the four bytes to produce an output word.
            temp = SubWord(temp);

            temp[0] ^= Rcon[i];

            for (int j = 0; j < 16; ++j) {
                expandedKeys[i][j] = expandedKeys[i-1][j] ^ temp[j % 4];
            }
        }

        return expandedKeys;
    }
*/
private:

    static const std::array<uint32_t, 11> Rcon;

    // This is the S-Box used in AES.
    static const uint8_t sBox[16][16];

    // Define the inverse S-box
    static const uint8_t invSBox[16][16];

   
    static void InvSubBytes(std::array<uint8_t, 16>& state) {
        for (int i = 0; i < 16; ++i) {
            uint8_t row = (state[i] & 0xF0) >> 4;
            uint8_t col = state[i] & 0x0F;
            state[i] = invSBox[row][col];
        }
    }


    static void InvShiftRows(std::array<uint8_t, 16>& state) {
        std::array<uint8_t, 16> temp = state;

        // Row 0 does not change
        // Row 1
        state[4+0] = temp[4+3];
        state[4+1] = temp[4+0];
        state[4+2] = temp[4+1];
        state[4+3] = temp[4+2];

        // Row 2
        state[8+0] = temp[8+3];
        state[8+1] = temp[8+0];
        state[8+2] = temp[8+1];
        state[8+3] = temp[8+2];

        // Row 3
        state[12+0] = temp[12+3];
        state[12+1] = temp[12+0];
        state[12+2] = temp[12+1];
        state[12+3] = temp[12+2];
    }


    static void InvMixColumns(std::array<uint8_t, 16>& state) {
        const std::array<std::array<uint8_t, 4>, 4> matrix = {
            std::array<uint8_t, 4>({0x0E, 0x0B, 0x0D, 0x09}),
            std::array<uint8_t, 4>({0x09, 0x0E, 0x0B, 0x0D}),
            std::array<uint8_t, 4>({0x0D, 0x09, 0x0E, 0x0B}),
            std::array<uint8_t, 4>({0x0B, 0x0D, 0x09, 0x0E})
        };

        for (int c = 0; c < 4; ++c) {
            std::array<uint8_t, 4> column = {state[4*c], state[4*c + 1], state[4*c + 2], state[4*c + 3]};
            for (int i = 0; i < 4; ++i) {
                state[4*c + i] = gmul(matrix[i][0], column[0]) ^ gmul(matrix[i][1], column[1])
                    ^ gmul(matrix[i][2], column[2]) ^ gmul(matrix[i][3], column[3]);
            }
        }
    }


    static void SubBytes(std::array<uint8_t, 16>& state) {
        
        for (auto& byte : state) {
            byte = AES::sBox[byte / 16][byte % 16];
        }
    }


    static void ShiftRows(std::array<uint8_t, 16>& state) {
        std::array<uint8_t, 16> temp = state;

        // Row 0, no shift

        // Row 1
        state[4] = temp[5]; state[5] = temp[6]; state[6] = temp[7]; state[7] = temp[4];

        // Row 2
        state[8+0] = temp[8+1]; state[8+1] = temp[8+2]; state[8+2] = temp[8+3]; state[8+3] = temp[8+0];

        // Row 3
        state[12+0] = temp[12+1]; state[12+1] = temp[12+2]; state[12+2] = temp[12+3]; state[12+3] = temp[12+0];
    }


/*
This function performs multiplication in the Galois field GF(2^8)
| 2 3 1 1 |
| 1 2 3 1 |
| 1 1 2 3 |
| 3 1 1 2 |
*/
    static uint8_t gmul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        uint8_t high_bit_mask = 0x80;
        uint8_t high_bit = 0;
        uint8_t modulo = 0x1B; /* x^8 + x^4 + x^3 + x + 1 */

        for (int i = 0; i < 8; i++) {
            if (b & 1) {
                p ^= a;
            }

            high_bit = a & high_bit_mask;
            a <<= 1;
            if (high_bit) {
                a ^= modulo;
            }
            b >>= 1;
        }

        return p;
    }

    static void MixColumns(std::array<uint8_t, 16>& state) {
        std::array<uint8_t, 16> tmp = state;

        for (int i = 0; i < 4; ++i) {
            state[i*4 + 0] = gmul(tmp[i*4 + 0], 0x02) ^ gmul(tmp[i*4 + 1], 0x03) ^ tmp[i*4 + 2] ^ tmp[i*4 + 3];
            state[i*4 + 1] = tmp[i*4 + 0] ^ gmul(tmp[i*4 + 1], 0x02) ^ gmul(tmp[i*4 + 2], 0x03) ^ tmp[i*4 + 3];
            state[i*4 + 2] = tmp[i*4 + 0] ^ tmp[i*4 + 1] ^ gmul(tmp[i*4 + 2], 0x02) ^ gmul(tmp[i*4 + 3], 0x03);
            state[i*4 + 3] = gmul(tmp[i*4 + 0], 0x03) ^ tmp[i*4 + 1] ^ tmp[i*4 + 2] ^ gmul(tmp[i*4 + 3], 0x02);
        }
    }


    static void AddRoundKey(std::array<uint8_t, 16>& state, const std::array<uint8_t, 16>& roundKey) {
        for (int i = 0; i < 16; ++i) {
            state[i] ^= roundKey[i];
        }
    }

  static std::array<uint8_t, 4> SubWord(std::array<uint8_t, 4> word) {
      for (auto& byte : word) {
          byte = AES::sBox[byte / 16][byte % 16];
      }
      return word;
  }

  static uint32_t SubWord(uint32_t word) {
      for (int i = 0; i < 4;i++) {
          uint8_t byte = (word>>(i*4))&0xff;
          word = (word&(~(0xff<<((3-i)*4)))) | (AES::sBox[byte / 16][byte % 16]<<((3-i)*4));
      }
      return word;
  }

  static std::array<uint8_t, 4> RotWord(std::array<uint8_t, 4> word) {
      uint8_t temp = word[0];
      word[0] = word[1];
      word[1] = word[2];
      word[2] = word[3];
      word[3] = temp;
      return word;
  }
  static uint32_t RotWord(uint32_t word) {
      return (word<<8) | (word>>24);
  }
};

// This is the Rcon table used in AES.
const std::array<uint32_t, 11> AES::Rcon = {
    0x00000000, 0x01000000, 0x02000000,
		0x04000000, 0x08000000, 0x10000000, 
		0x20000000, 0x40000000, 0x80000000, 
		0x1b000000, 0x36000000
};

// This is the S-Box used in AES.
const uint8_t AES::sBox[16][16] = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};

// Define the inverse S-box
const uint8_t AES::invSBox[16][16] = {
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
};

#include <fstream>

int main() {
    std::array<uint8_t, 16> plaintext = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    std::array<uint8_t, 16> key = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
                                    //0x76, 0x2e, 0x71, 0x60, 0xf1, 0x83, 0x51, 0x51, 
                                    //0x8a, 0x09, 0x53, 0x2a, 0x39, 0x09, 0x09, 0x7d};
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
