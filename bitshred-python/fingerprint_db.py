import os
from itertools import combinations
import pickle
import logging

from binary_file import BinaryFile, initailaize_binary_file


FINGERPRINT_DB = 'fingerprints.pkl'


def compare_fingerprint_db(db: str):
    fingerprints = pickle.load(open(os.path.join(db, FINGERPRINT_DB), 'rb'))
    for file_a, file_b in combinations(fingerprints.keys(), 2):
        similarity = jaccard_distance(fingerprints[file_a], fingerprints[file_b])
        logging.info(f'{file_a} vs {file_b}: {similarity=}')

def update_fingerprint_db(binary: str, shred_size: int, window_size: int, fp_size: int, db: str) -> None:
    """Compute the fingerprints of all the samples in `binary` directory and store them in `fingerprints.pkl`
    """

    fingerprints: dict[str, bytearray] = {}
    for root, _, files in os.walk(binary):
        for file in files:
            sample = os.path.join(root, file)

            binary_file = initailaize_binary_file(sample)
            if not binary_file:
                continue
            
            logging.debug(binary_file)
            shred_hashes = shred_section(binary_file, shred_size)

            if len(shred_hashes) < window_size:
                logging.warning(f'{sample} skipped (no appropriate sections)')
                continue

            fingerprint = create_fingerprint(shred_hashes, fp_size, window_size)
            fingerprints[file] = fingerprint

    pickle.dump(fingerprints, open(os.path.join(db, FINGERPRINT_DB), 'wb'))

def create_fingerprint(shred_hashes: list[int], fp_size: int, window_size: int) -> bytearray:
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
                if shred_hashes[i+j] <= min_hash:
                    min_hash = shred_hashes[i+j]
                    min_hash_idx = i + j
            bit_vector_set(bit_vector, min_hash & (fp_size_bits - 1))
        else:  # min_hash_idx is in current window
            if shred_hashes[i+window_size-1] <= min_hash:
                min_hash = shred_hashes[i+window_size-1]
                min_hash_idx = i + window_size - 1
                bit_vector_set(bit_vector, min_hash & (fp_size_bits - 1))
    
    return bit_vector

def shred_section(binary_file: BinaryFile, shred_size: int) -> list[int]:
    logging.debug(f'Shredding {binary_file.filename}')

    shred_hashes = []
    for section in binary_file.sections:
        if (
            not section.is_code or
            not (section.vma <= binary_file.start_addr <= section.vma + section.data_size) and
            section.name not in ('.text', 'CODE')
        ):
            logging.debug(f'Skipping section {section.name}: {section}')
            continue

        if section.data_size < shred_size:
            logging.warning(f'Invalid size for section {section.name}: {section.data_size=}, {shred_size=}')
            continue

        logging.debug(f'Processing section {section.name}: {section.data_size=}, {shred_size=}')

        section_shred_num = section.data_size - shred_size + 1
        for i in range(section_shred_num):
            shred = section.data[i:i+shred_size]
            shred_hash = djb2_hash(shred)
            shred_hashes.append(shred_hash)

        logging.debug(f'Finished processing section {section.name}')
        logging.debug(f'{shred_hashes[:5]=}')

    return shred_hashes

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

def jaccard_distance(fp_a: bytearray, fp_b: bytearray) -> float:
    bit_vector_intersection = 0
    for byte_a, byte_b in zip(fp_a, fp_b):
        bit_vector_intersection += bit_count(byte_a & byte_b)

    bit_count_a = bit_count(fp_a)
    bit_count_b = bit_count(fp_b)
    bit_vector_union = bit_count_a + bit_count_b - bit_vector_intersection

    return bit_vector_intersection / bit_vector_union

def bit_count(bit_vector: bytearray | int, /) -> int:
    if isinstance(bit_vector, int):
        return bin(bit_vector).count('1')
    elif isinstance(bit_vector, bytearray):
        return sum(bin(byte).count('1') for byte in bit_vector)
    else:
        error_msg = f'Unsupported type for bit count: {type(bit_vector)}'
        logging.error(error_msg)
        raise TypeError(error_msg)
