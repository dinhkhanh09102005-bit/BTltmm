from typing import Union
from .sbox import SBOX

# Hang so vong cua AES-128
RCON = (
    0x00,
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
)

ByteData = Union[bytes, bytearray, memoryview]

def _validate_input(
    data: ByteData,
    expected_len: int,
    name: str,
) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"{name} must be bytes, bytearray, or memoryview"
        )
    data_bytes = bytes(data)
    if len(data_bytes) != expected_len:
        raise ValueError(
            f"{name} length must be exactly {expected_len} bytes"
        )
    return data_bytes
def _rot_word(word: bytes) -> bytes:
    return word[1:] + word[:1]

def _sub_word(word: bytes) -> bytes:
    return bytes(SBOX[value] for value in word)