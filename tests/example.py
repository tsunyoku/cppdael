from base64 import b64decode
from py3rijndael import RijndaelCbc, ZeroPadding

from cppdael import encrypt, decrypt, decrypt_string, Rijndael, MODE_CBC
import timeit

RUN_COUNT = 1000  # how many times it should run the func to get an accurate average

key = "osu!-scoreburgr---------20211103"
iv = b64decode("8cpBI5PTxOlfDqXN9dE2OBothneHAmQZlN99K6zEkxI=")
cipher = b64decode(
    "2rQUjbqnBfb5CdnfcdACG+IjeYlTkE9cHxD3y1aPxkHQVSa5ZCHb/gS2lV95U5C6K5zcMwZVc/q1OpPR5A4i7+s3NTR2jIzuh7dfLT260+HhHh/nlDENYDvVML3PHBxTzmjKgaN66XfZ/RrGRre3TwqvwEnMc6rrga97MZBAG8UdZmbMOwEeDhKhva6x9tagmorT8BqzNpD3w+L4+wKGXg=="
)
decrypted_value = b"62ec0dcd994ccd1b385f90c0a8b3c4d3:tsunyoku :1cb0428f1646ac39168121b322872824:57:2:0:14:2:1:17810:62:False:F:144:False:0:211127230146:20211103\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14"


def decrypt_cpp_string():
    return decrypt_string(cipher, key, iv)


def decrypt_cpp_bytes():
    return decrypt(MODE_CBC, 32, key.encode(), iv, cipher, 32)


def decrypt_cpp_cls():
    return Rijndael(MODE_CBC, 32, key.encode(), iv).decrypt(cipher)


def decrypt_py():
    aes = RijndaelCbc(key=key, iv=iv, padding=ZeroPadding(32), block_size=32)
    return aes.decrypt(cipher)

# generate tests for pytest
for func in [decrypt_cpp_string, decrypt_cpp_bytes, decrypt_cpp_cls, decrypt_py]:
    exec(f"def test_{func.__name__}():\n    assert func() == decrypted_value")

if __name__ == "__main__":
    tests = []
    for func in [decrypt_cpp_string, decrypt_cpp_bytes, decrypt_cpp_cls, decrypt_py]:
        # 1. assert correctnes
        fname = func.__name__
        try:
            assert decrypted_value == func()
        except:
            print(f"{fname} failed to produce a correct result")

        total = timeit.timeit(func, number=RUN_COUNT)
        avg = total * 1000 / RUN_COUNT
        print(f"Time taken to run {fname}: {avg:.2f}ms")
