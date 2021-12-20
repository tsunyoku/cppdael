#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "rijndael.h"

typedef struct
{
    PyObject_HEAD
        CRijndael rj;
    uint8_t mode;
} RijndaelObject;

static int
Rijndael_init(RijndaelObject *self, PyObject *args, PyObject *kwds)
{
    int mode;
    int block_size;
    char *key;
    Py_ssize_t key_size;
    char *iv;
    Py_ssize_t iv_size;
    int hard_key_size = 0;
    if (!PyArg_ParseTuple(args, "iiy#y#y#|i", &mode, &block_size, &key, &key_size, &iv, &iv_size, &hard_key_size))
        return NULL;

    // check input
    if (mode > CRijndael::CFB)
    {
        PyErr_SetString(PyExc_ValueError, "invalid mode (ECB = 0, CBC = 1, CFB = 2)");
        return -1;
    }
    self->mode = mode;
    if (block_size != 16 && block_size != 24 && block_size != 32)
    {
        PyErr_SetString(PyExc_ValueError, "invalid block size");
        return -1;
    }

    // fix key size if necessary
    if (hard_key_size == 0)
        hard_key_size = key_size;
    if (hard_key_size % 8)
    {
        hard_key_size += 8 - (hard_key_size % 8);
    }
    if (hard_key_size > 32)
    {
        hard_key_size = 32;
    }

    // set key and iv
    char Key[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    char IV[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    memcpy(Key, key, (key_size > 32) ? 32 : key_size);
    memcpy(IV, iv, (iv_size > 32) ? 32 : iv_size);

    // make key
    self->rj.MakeKey(Key, IV, hard_key_size, block_size);
    return 0;
}

static void Rijndael_dealloc(RijndaelObject *self)
{
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
Rijndael_getKeyLength(RijndaelObject *self, void *closure)
{
    return PyLong_FromLong(self->rj.GetKeyLength());
}

static PyObject *
Rijndael_getBlockSize(RijndaelObject *self, void *closure)
{
    return PyLong_FromLong(self->rj.GetBlockSize());
}

static PyObject *
Rijndael_getRounds(RijndaelObject *self, void *closure)
{
    return PyLong_FromLong(self->rj.GetRounds());
}

static PyObject *
Rijndael_getMode(RijndaelObject *self, void *closure)
{
    return PyLong_FromLong((long)self->mode);
}

static int
Rijndael_setMode(RijndaelObject *self, PyObject *value, void *closure)
{
    unsigned long mode = PyLong_AsUnsignedLong(value);
    if (mode > CRijndael::CFB)
    {
        PyErr_SetString(PyExc_ValueError, "invalid mode (ECB = 0, CBC = 1, CFB = 2)");
        return -1;
    }
    self->mode = (uint8_t)mode;
    return 0;
}

static PyGetSetDef Rijndael_getsetters[] = {
    {"key_length", (getter)Rijndael_getKeyLength, NULL,
     "length of the key", NULL},
    {"block_size", (getter)Rijndael_getBlockSize, NULL,
     "size of the block", NULL},
    {"rounds", (getter)Rijndael_getRounds, NULL, "number of rounds", NULL},
    {"mode", (getter)Rijndael_getMode, (setter)Rijndael_setMode, "encryption mode", NULL},
    {NULL} /* Sentinel */
};

static PyObject *Rijndael_EncryptBlock(RijndaelObject *self, PyObject *args)
{
    char *in;
    Py_ssize_t in_size;

    if (!PyArg_ParseTuple(args, "y#", &in, &in_size))
        return NULL;
    char *out = (char *)PyMem_Malloc(in_size);
    PyObject *ret = NULL;
    try
    {
        self->rj.EncryptBlock(in, out);
        ret = Py_BuildValue("y#", out, in_size);
    }
    catch (...)
    {
        PyErr_SetString(PyExc_ValueError, "unknown error occured during the encryption");
    }

    PyMem_Free(out);
    return ret;
}

static PyObject *Rijndael_DecryptBlock(RijndaelObject *self, PyObject *args)
{
    char *in;
    Py_ssize_t in_size;

    if (!PyArg_ParseTuple(args, "y#", &in, &in_size))
        return NULL;
    char *out = (char *)PyMem_Malloc(in_size);
    PyObject *ret = NULL;
    try
    {
        self->rj.DecryptBlock(in, out);
        ret = Py_BuildValue("y#", out, in_size);
    }
    catch (...)
    {
        PyErr_SetString(PyExc_ValueError, "unknown error occured during the encryption");
    }

    PyMem_Free(out);
    return ret;
}

static PyObject *Rijndael_Encrypt(RijndaelObject *self, PyObject *args)
{
    char *in;
    Py_ssize_t in_size;

    if (!PyArg_ParseTuple(args, "y#", &in, &in_size))
        return NULL;

    char *out = (char *)PyMem_Malloc(in_size);
    PyObject *ret = NULL;
    try
    {
        self->rj.Encrypt(in, out, in_size, self->mode);
        ret = Py_BuildValue("y#", out, in_size);
    }
    catch (...)
    {
        PyErr_SetString(PyExc_ValueError, "unknown error occured during the encryption");
    }

    PyMem_Free(out);
    return ret;
}

static PyObject *Rijndael_Decrypt(RijndaelObject *self, PyObject *args)
{
    char *in;
    Py_ssize_t in_size;

    if (!PyArg_ParseTuple(args, "y#", &in, &in_size))
        return NULL;

    char *out = (char *)PyMem_Malloc(in_size);
    PyObject *ret = NULL;
    try
    {
        self->rj.Decrypt(in, out, in_size, self->mode);
        ret = Py_BuildValue("y#", out, in_size);
    }
    catch (...)
    {
        PyErr_SetString(PyExc_ValueError, "unknown error occured during the decryption");
    }

    PyMem_Free(out);
    return ret;
}

static PyMethodDef Rijndael_methods[] = {
    {"encrypt_block", (PyCFunction)Rijndael_EncryptBlock, METH_VARARGS,
     PyDoc_STR("encrypts a block of data")},
    {"decrypt_block", (PyCFunction)Rijndael_DecryptBlock, METH_VARARGS,
     PyDoc_STR("decrypts a block of data")},
    {"encrypt", (PyCFunction)Rijndael_Encrypt, METH_VARARGS,
     PyDoc_STR("encrypts the given data")},
    {"decrypt", (PyCFunction)Rijndael_Decrypt, METH_VARARGS,
     PyDoc_STR("decrypts the given data")},
    {NULL},
};

/*  
############################################################################
    create RijndaelType and module for Python
############################################################################
*/

static PyTypeObject RijndaelType = {
    PyVarObject_HEAD_INIT(NULL, 0) "cppdael.Rijndael",                /* tp_name */
    sizeof(RijndaelObject),                                           /* tp_basicsize */
    0,                                                                /* tp_itemsize */
    (destructor)Rijndael_dealloc,                                     /* tp_dealloc */
    0,                                                                /* tp_vectorcall_offset */
    0,                                                                /* tp_getattr */
    0,                                                                /* tp_setattr */
    0,                                                                /* tp_as_async */
    /*(reprfunc)myobj_repr*/ 0,                                       /* tp_repr */
    0,                                                                /* tp_as_number */
    0,                                                                /* tp_as_sequence */
    0,                                                                /* tp_as_mapping */
    0,                                                                /* tp_hash */
    0,                                                                /* tp_call */
    0,                                                                /* tp_str */
    0,                                                                /* tp_getattro */
    0,                                                                /* tp_setattro */
    0,                                                                /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                                               /* tp_flags */
    "a Rijndael that allows an easy and fast parsing of binary data", /* tp_doc */
    0,                                                                /* tp_traverse */
    0,                                                                /* tp_clear */
    0,                                                                /* tp_richcompare */
    0,                                                                /* tp_weaklistoffset */
    0,                                                                /* tp_iter */
    0,                                                                /* tp_iternext */
    Rijndael_methods,                                                 /* tp_methods */
    0,                                                                /* tp_members */
    Rijndael_getsetters,                                              /* tp_getset */
    0,                                                                /* tp_base */
    0,                                                                /* tp_dict */
    0,                                                                /* tp_descr_get */
    0,                                                                /* tp_descr_set */
    0,                                                                /* tp_dictoffset */
    (initproc)Rijndael_init,                                          /* tp_init */
    0,                                                                /* tp_alloc */
    PyType_GenericNew,                                                /* tp_new */
};

static PyObject *decrypt_string(PyObject *self, PyObject *args)
{
    char *input;
    Py_ssize_t input_size;
    char *key;
    Py_ssize_t key_size;
    char *iv;
    Py_ssize_t iv_size;
    if (!PyArg_ParseTuple(args, "s#s#s#", &input, &input_size, &key, &key_size, &iv, &iv_size))
        return NULL;
    const std::string Input = std::string(input, input_size);
    const std::string Key = std::string(key, key_size);
    const std::string IV = std::string(iv, iv_size);
    std::string ret = decrypt_string(Input, Key, IV);
    return PyBytes_FromStringAndSize(ret.c_str(), ret.length());
}

static PyObject *decrypt(PyObject *self, PyObject *args)
{
    int mode;
    int block_size;
    char *input;
    Py_ssize_t input_size;
    char *key;
    Py_ssize_t key_size;
    char *iv;
    Py_ssize_t iv_size;
    int hard_key_size = 0;
    if (!PyArg_ParseTuple(args, "iiy#y#y#|i", &mode, &block_size, &key, &key_size, &iv, &iv_size, &input, &input_size, &hard_key_size))
        return NULL;

    // check input
    if (mode > CRijndael::CFB)
    {
        PyErr_SetString(PyExc_ValueError, "invalid mode (ECB = 0, CBC = 1, CFB = 2)");
        return NULL;
    }
    if (block_size != 16 && block_size != 24 && block_size != 32)
    {
        PyErr_SetString(PyExc_ValueError, "invalid block size");
        return NULL;
    }

    // fix key size if necessary
    if (hard_key_size == 0)
        hard_key_size = key_size;
    if (hard_key_size % 8)
    {
        hard_key_size += 8 - (hard_key_size % 8);
    }
    if (hard_key_size > 32)
    {
        hard_key_size = 32;
    }

    // set key and iv
    char Key[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    char IV[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    memcpy(Key, key, (key_size > 32) ? 32 : key_size);
    memcpy(IV, iv, (iv_size > 32) ? 32 : iv_size);


    // decrypt
    char *out = (char *)PyMem_Malloc(input_size);
    PyObject *ret = NULL;
    try
    {
        CRijndael rj;
        rj.MakeKey(Key, IV, hard_key_size, block_size);
        rj.Decrypt(input, out, input_size, mode);
        ret = Py_BuildValue("y#", out, input_size);
    }
    catch (...)
    {
        PyErr_SetString(PyExc_ValueError, "unknown error occured during the decryption");
    }

    PyMem_Free(out);
    return ret;
}

static PyObject *encrypt(PyObject *self, PyObject *args)
{
    int mode;
    int block_size;
    char *input;
    Py_ssize_t input_size;
    char *key;
    Py_ssize_t key_size;
    char *iv;
    Py_ssize_t iv_size;
    int hard_key_size = 0;
    if (!PyArg_ParseTuple(args, "iiy#y#y#|i", &mode, &block_size, &key, &key_size, &iv, &iv_size, &input, &input_size, &hard_key_size))
        return NULL;

    // check input
    if (mode > CRijndael::CFB)
    {
        PyErr_SetString(PyExc_ValueError, "invalid mode (ECB = 0, CBC = 1, CFB = 2)");
        return NULL;
    }
    if (block_size != 16 && block_size != 24 && block_size != 32)
    {
        PyErr_SetString(PyExc_ValueError, "invalid block size");
        return NULL;
    }

    // fix key size if necessary
    if (hard_key_size == 0)
        hard_key_size = key_size;
    if (hard_key_size % 8)
    {
        hard_key_size += 8 - (hard_key_size % 8);
    }
    if (hard_key_size > 32)
    {
        hard_key_size = 32;
    }

    // set key and iv
    char Key[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    char IV[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    memcpy(Key, key, (key_size > 32) ? 32 : key_size);
    memcpy(IV, iv, (iv_size > 32) ? 32 : iv_size);


    // encrypt
    char *out = (char *)PyMem_Malloc(input_size);
    PyObject *ret = NULL;
    try
    {
        CRijndael rj;
        rj.MakeKey(Key, IV, hard_key_size, block_size);
        rj.Encrypt(input, out, input_size, mode);
        ret = Py_BuildValue("y#", out, input_size);
    }
    catch (...)
    {
        PyErr_SetString(PyExc_ValueError, "unknown error occured during the encryption");
    }

    PyMem_Free(out);
    return ret;
}

// Exported methods are collected in a table
static struct PyMethodDef method_table[] = {
    {"decrypt_string",
     (PyCFunction)decrypt_string,
     METH_VARARGS,
     ""},
    {"decrypt",
     (PyCFunction)decrypt,
     METH_VARARGS,
     ""},
    {"encrypt",
     (PyCFunction)encrypt,
     METH_VARARGS,
     ""},
    {NULL,
     NULL,
     0,
     NULL} // Sentinel value ending the table
};

static PyModuleDef cppdael_module = {
    PyModuleDef_HEAD_INIT,
    "cppdael",
    "a Rijndael that allows an easy and fast parsing of binary data",
    -1,
    method_table,
    NULL, // Optional slot definitions
    NULL, // Optional traversal function
    NULL, // Optional clear function
    NULL  // Optional module deallocation function
};

PyMODINIT_FUNC
PyInit_cppdael(void)
{
    PyObject *m;
    if (PyType_Ready(&RijndaelType) < 0)
        return NULL;

    m = PyModule_Create(&cppdael_module);
    if (m == NULL)
        return NULL;

    Py_INCREF(&RijndaelType);
    if (PyModule_AddObject(m, "Rijndael", (PyObject *)&RijndaelType) < 0)
    {
        Py_DECREF(&RijndaelType);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}