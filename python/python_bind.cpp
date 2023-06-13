// g++ -fPIC -c -o python_bind.o python_bind.cpp
// gcc -shared -o aes_lib.so python_bind.o -lstdc++


#include <array>
#include <cstdint>
#include <algorithm>
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#define NPY_NO_DEPRECATED_API NPY_1_7_API_VERSION
#include "numpy\ndarraytypes.h"
#include "numpy\ndarrayobject.h"
#include "numpy\arrayobject.h"

#include "../fcryptolib.hpp"

extern "C" {

    static PyObject *method_encrypt(PyObject *module, PyObject *args) {

        const char* key;
        const char* plaintext;
        Py_ssize_t key_len, plaintext_len;
        char *ciphertext;
        
        /* Parse arguments */
        if(!PyArg_ParseTuple(args, "y#y#", &plaintext,&plaintext_len, &key, &key_len)) {
            PyErr_SetString(PyExc_ValueError, "Inputs must be (plaintext, key)");
            return NULL;
        }        
        if(key_len != 16) {
            PyErr_SetString(PyExc_ValueError, "Key must be 16 bytes long");
            return NULL;
        }
        if(plaintext_len != 16) {
            PyErr_SetString(PyExc_ValueError, "Plaintext must be 16 bytes long");
            return NULL;
        }

        std::string plaintext_str(plaintext, 16);
        std::string key_str(key, key_len);

        std::array<uint8_t, 16> plaintext_arr, key_arr, ciphertext_arr;
        std::copy(plaintext_str.begin(), plaintext_str.end(), plaintext_arr.begin());
        std::copy(key_str.begin(), key_str.end(), key_arr.begin());

        AES::encrypt(plaintext_arr, ciphertext_arr, key_arr);

        ciphertext = (char*)malloc(16);
        std::copy(ciphertext_arr.begin(), ciphertext_arr.end(), (uint8_t*)ciphertext);

        
        npy_intp dims[1] = {16};
      
        PyObject* arr_return = PyArray_SimpleNewFromData(1, dims, NPY_UINT8, (uint8_t*)ciphertext);
        PyArray_ENABLEFLAGS((PyArrayObject *)arr_return, NPY_ARRAY_OWNDATA);
        return Py_BuildValue("N", arr_return);
    }

    static PyObject *method_decrypt(PyObject *module, PyObject *args) {
        const char* key;
        const char* ciphertext;
        Py_ssize_t key_len, ciphertext_len;
        char* plaintext;

        
        /* Parse arguments */
        if(!PyArg_ParseTuple(args, "y#y#", (char**)&ciphertext,&ciphertext_len, (char**)&key, &key_len)) {
            return NULL;
        }
        if(key_len != 16) {
            PyErr_SetString(PyExc_ValueError, "Key must be 16 bytes long");
            return NULL;
        }
        if(ciphertext_len != 16) {
            PyErr_SetString(PyExc_ValueError, "Ciphertext must be 16 bytes long");
            return NULL;
        }

        std::string ciphertext_str(ciphertext, 16);
        std::string key_str(key, key_len);

        std::array<uint8_t, 16> plaintext_arr, key_arr, ciphertext_arr;
        std::copy(ciphertext_str.begin(), ciphertext_str.end(), ciphertext_arr.begin());
        std::copy(key_str.begin(), key_str.end(), key_arr.begin());
        
        AES::decrypt(ciphertext_arr, plaintext_arr, key_arr);

        plaintext = (char*)malloc(16);

        std::copy(plaintext_arr.begin(), plaintext_arr.end(), (uint8_t*)plaintext);

        
        npy_intp dims[1] = {16};
        PyObject* arr_return = PyArray_SimpleNewFromData(1, dims, NPY_UINT8, (uint8_t*)plaintext);
        PyArray_ENABLEFLAGS((PyArrayObject *)arr_return, NPY_ARRAY_OWNDATA);
        return Py_BuildValue("N", arr_return);
      }


    static PyMethodDef fcryptolibMethods[] = {
        {"encrypt", method_encrypt, METH_VARARGS, "AES-128 encryption"},
        {"decrypt", method_decrypt, METH_VARARGS, "AES-128 decryption"},
        {NULL, NULL, 0, NULL}
    };

    PyDoc_STRVAR(fcryptolib_doc, "fCryptoLib encryption and decryption module");

    static struct PyModuleDef fcryptolibmodule = {
        PyModuleDef_HEAD_INIT,
        "fcryptolib_fador",
        fcryptolib_doc,
        -1,
        fcryptolibMethods,
        NULL,
        NULL,
        NULL,
        NULL
    };

    PyMODINIT_FUNC PyInit_fcryptolib_fador(void) {
        import_array();
        return PyModule_Create(&fcryptolibmodule);
    }
}