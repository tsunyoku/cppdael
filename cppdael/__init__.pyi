from typing import Literal, Optional

MODE_ECB: Literal[0]
MODE_CBC: Literal[1]
MODE_CFB: Literal[2]

BlockCipherMode = Literal[0, 1, 2]
RijndaelBlockSize = Literal[16, 24, 32]

def decrypt_string(cipher: str, key: str, iv: str) -> str: ...
def decrypt(
    block_cipher_mode: BlockCipherMode,
    block_size: RijndaelBlockSize,
    key: bytes,
    iv: bytes,
    cipher: bytes,
    hard_key_size: Optional[int] = None,
) -> bytes: ...
def encrypt(
    block_cipher_mode: BlockCipherMode,
    block_size: RijndaelBlockSize,
    key: bytes,
    iv: bytes,
    plain_text: bytes,
    hard_key_size: Optional[int] = None,
) -> bytes: ...

RijndaelKeySize = Literal[16, 24, 32]
RijndaelRounds = Literal[10, 12, 14]

class Rijndael:
    mode: BlockCipherMode
    block_size: RijndaelBlockSize
    key_length: RijndaelKeySize
    rounds: RijndaelRounds
    def __init__(
        self,
        mode: BlockCipherMode,
        block_size: RijndaelBlockSize,
        key: bytes,
        iv: bytes,
        hard_key_size: Optional[int] = None,
    ) -> None: ...
    def decrypt(self, cipher: bytes) -> bytes: ...
    def encrypt(self, plain_text: bytes) -> bytes: ...
