# Fador's crypto library

This project provides a simple implementation of crypto algorithms in C++.
Currently only thing supported is AES (Advanced Encryption Standard), specifically focusing on AES-128 in ECB (Electronic Codebook) and CBC (Cipher Block Chaining) modes.

## WARNING

This implementation is created for educational purposes and should NOT be used for security-critical applications. This code lacks many features and safeguards that a secure encryption system requires. In a real-world application, always use a well-reviewed cryptographic library that provides these necessary features and has been tested for security vulnerabilities.

## Features

- AES-128 encryption/decryption in ECB mode
- AES-128 encryption/decryption in CBC mode
- Key Expansion
- Various helper functions (SubBytes, ShiftRows, MixColumns, AddRoundKey, etc.)

## Building and Running the Project

This project is a simple single-file C++ program. To build it, you'll need a C++ compiler that supports at least the C++11 standard.

Here's how to build the project:

```bash
g++ -std=c++11 -o aes128 AES128_test.cpp
```

Then, you can run it like so:

```bash
./aes128
```

This will run the program with a predefined plaintext and key, outputting the original text, the encrypted text, and the decrypted text.

## Python

The project includes an experimental python interface, which can be built and tested by going to `python/` and running:

```bash
python setup.py bdist_wheel
pip install dist/fcryptolib_fador*.whl
python tests/simple_test.py
```


## License

This project is licensed under permissive BSD 2-Clause License. - see the [LICENSE](LICENSE) file for details.
