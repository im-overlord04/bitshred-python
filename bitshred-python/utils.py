def bit_vector_set(vector: bytearray, offset: int) -> None:
    byte_index = offset >> 3
    bit_mask = 1 << (offset & 0x7)
    vector[byte_index] |= bit_mask


def djb2_hash(data: bytes) -> int:
    hash = 5381
    for byte in data:
        hash = hash * 33 + byte
    # limits the hash to 32 bits (unsigned int)
    return hash & 0xFFFFFFFF


def bit_count(fingerprint: bytearray) -> int:
    return sum(byte.bit_count() for byte in fingerprint)
