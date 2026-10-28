from collections.abc import Sequence
from typing import Union
from .transforms import sub_bytes, shift_rows, mix_columns, add_round_key

ByteData = Union[bytes, bytearray, memoryview]

def encrypt_block(round_keys: Sequence[bytes], block: ByteData) -> bytes:
    """Ma hoa mot khoi 16 byte bang AES-128 chuan."""
    if not isinstance(block, (bytes, bytearray, memoryview)):
        raise TypeError("block must be bytes, bytearray, or memoryview")
    block = bytes(block)
    if len(block) != 16:
        raise ValueError("block length must be exactly 16 bytes")
