import reprlib
from dataclasses import dataclass
from typing import Literal

from utils import bit_count, bit_vector_set


@dataclass
class Fingerprint:
    bit_vector: bytearray
    bit_count: int


def fingerprint_encoder(fingerprint: Fingerprint) -> dict[str, str | int]:
    return {
        'bit_vector': reprlib.repr(fingerprint.bit_vector.hex()),
        'bit_count': fingerprint.bit_count,
    }


def create_fingerprint(shred_hashes: list[int], fp_size: int, window_size: int) -> Fingerprint:
    fp_size_bytes = fp_size * 1024  # fp_size is in KB
    fp_size_bits = fp_size_bytes * 8

    bit_vector = bytearray(fp_size_bytes)
    min_hash_idx = -1
    for i in range(len(shred_hashes) - window_size + 1):
        # current window is shred_hashes[i:i+window_size]

        if min_hash_idx < i:  # min_hash_idx is not in current window
            min_hash = shred_hashes[i]
            min_hash_idx = i
            for j in range(1, window_size):
                if shred_hashes[i + j] <= min_hash:
                    min_hash = shred_hashes[i + j]
                    min_hash_idx = i + j
            bit_vector_set(bit_vector, min_hash & (fp_size_bits - 1))
        else:  # min_hash_idx is in current window
            if shred_hashes[i + window_size - 1] <= min_hash:
                min_hash = shred_hashes[i + window_size - 1]
                min_hash_idx = i + window_size - 1
                bit_vector_set(bit_vector, min_hash & (fp_size_bits - 1))

    return Fingerprint(bit_vector, bit_count(bit_vector))


def jaccard_distance(fp_a: Fingerprint, fp_b: Fingerprint) -> float:
    byteorder: Literal['little', 'big'] = 'little'
    fp_a_bit_vector = int.from_bytes(fp_a.bit_vector, byteorder=byteorder)
    fp_b_bit_vector = int.from_bytes(fp_b.bit_vector, byteorder=byteorder)
    bit_vector_intersection = (fp_a_bit_vector & fp_b_bit_vector).bit_count()

    bit_vector_union = fp_a.bit_count + fp_b.bit_count - bit_vector_intersection

    return bit_vector_intersection / bit_vector_union
