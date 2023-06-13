from setuptools import setup, Extension
import numpy

# define the extension module
aes_module = Extension('fcryptolib_fador', sources=['./src/fcryptolib_fador/python_bind.cpp'],
                        include_dirs=[numpy.get_include()])

# run the setup
setup(
    name='fcryptolib_fador',
    version='0.1.0',
    description='Python interface for AES-128 implemented in C++',
    ext_modules=[aes_module],
)
