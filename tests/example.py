from base64 import b64decode
from py3rijndael import RijndaelCbc, ZeroPadding

import cppdael
import timeit

key = "osu!-scoreburgr---------20211103"
iv = b64decode("8cpBI5PTxOlfDqXN9dE2OBothneHAmQZlN99K6zEkxI=")
cipher = b64decode("2rQUjbqnBfb5CdnfcdACG+IjeYlTkE9cHxD3y1aPxkHQVSa5ZCHb/gS2lV95U5C6K5zcMwZVc/q1OpPR5A4i7+s3NTR2jIzuh7dfLT260+HhHh/nlDENYDvVML3PHBxTzmjKgaN66XfZ/RrGRre3TwqvwEnMc6rrga97MZBAG8UdZmbMOwEeDhKhva6x9tagmorT8BqzNpD3w+L4+wKGXg==")

def decrypt_bindings(): return cppdael.decrypt(cipher, key, iv)

def decrypt_py():
    aes = RijndaelCbc(
        key=key,
        iv=iv,
        padding=ZeroPadding(32),
        block_size=32
    )

    return aes.decrypt(cipher)

if __name__ == "__main__":
    python = timeit.timeit("decrypt_py()", setup="from __main__ import decrypt_py", number=100)
    cpp = timeit.timeit("decrypt_bindings()", setup="from __main__ import decrypt_bindings", number=100)

    print(
        f'Time taken to run python decryption: {python * 1000:.2f}ms\n'
        f'Time taken to run c++ decryption: {cpp * 1000:.2f}ms'
    )