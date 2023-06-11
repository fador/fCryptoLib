from setuptools import setup, Extension

# define the extension module
aes_module = Extension('fCryptoLib', sources=['python_bind.cpp', 'aes.py'])

# run the setup
setup(
    name='fCryptoLib',
    version='1.0',
    description='Python interface for AES-128 implemented in C++',
    ext_modules=[aes_module],
)
