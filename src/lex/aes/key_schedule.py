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
def expand_key(key: ByteData) -> tuple[bytes, ...]:
    key = _validate_input(key, 16, "key")
    words = [
        key[i:i + 4]
        for i in range(0, 16, 4)
    ]
    for i in range(4, 44):
        temp = words[i - 1]
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp))

            rcon_value = bytes((RCON[i // 4], 0, 0, 0))
            temp = bytes(
                a ^ b for a, b in zip(temp, rcon_value)
            )
        new_word = bytes(
            a ^ b for a, b in zip(words[i - 4], temp)
        )
        words.append(new_word)
    round_keys = tuple(
        b"".join(words[i:i + 4])
        for i in range(0, 44, 4)
    )

    return round_keys