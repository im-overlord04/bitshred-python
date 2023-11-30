import logging
import os
import pickle
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from itertools import combinations
from time import perf_counter

from binary_file import BinaryFile, initailaize_binary_file

FINGERPRINT_DB = 'fingerprints.pkl'
JACCARD_DB = 'jaccard.pkl'
MAX_SET_BITS_RATIO = 0.8
MULTIPROCESSING = True


@dataclass
class Fingerprint:
    bit_vector: bytearray
    bit_count: int


def compare_fingerprint_db(db: str):
    """
    Compare the fingerprints of all the samples in `fingerprints.pkl` pairwise using Jaccard distance
    and store the results in `jaccard.pkl`
    """
    # for performance measurement
    start_time: float = perf_counter()

    fingerprints = pickle.load(open(os.path.join(db, FINGERPRINT_DB), 'rb'))
    jaccard_distances: dict[frozenset[str], float] = {}
    if MULTIPROCESSING:
        with ProcessPoolExecutor() as executor:
            to_do_map = {}
            for file_a, file_b in combinations(fingerprints.keys(), 2):
                future = executor.submit(
                    jaccard_distance, fingerprints[file_a], fingerprints[file_b]
                )
                to_do_map[future] = (file_a, file_b)

            for future in as_completed(to_do_map):
                file_a, file_b = to_do_map[future]
                similarity = future.result()
                jaccard_distances[frozenset([file_a, file_b])] = similarity
                logging.debug(f'{file_a} vs {file_b}: {similarity=}')
    else:
        for file_a, file_b in combinations(fingerprints.keys(), 2):
            similarity = jaccard_distance(fingerprints[file_a], fingerprints[file_b])
            jaccard_distances[frozenset([file_a, file_b])] = similarity
            logging.debug(f'{file_a} vs {file_b}: {similarity=}')

    pickle.dump(jaccard_distances, open(os.path.join(db, JACCARD_DB), 'wb'))

    elapsed_time = perf_counter() - start_time
    logging.info('--------------- Comparing Database ---------------')
    logging.info(f'# of viruses : {len(fingerprints)}')
    logging.info(f'Time         : {elapsed_time // 60:.0f}min{elapsed_time % 60:.3f}sec')


def update_fingerprint_db(
    binary: str, shred_size: int, window_size: int, fp_size: int, db: str
) -> None:
    """
    Compute the fingerprints of all the samples in `binary` directory and store them in `fingerprints.pkl`
    """
    # for performance measurement
    start_time: float = perf_counter()

    fingerprints: dict[str, Fingerprint] = {}
    if MULTIPROCESSING:
        with ProcessPoolExecutor() as executor:
            to_do_map = {}
            for root, _, files in os.walk(binary):
                for file in files:
                    sample = os.path.join(root, file)
                    future = executor.submit(
                        process_sample, sample, shred_size, window_size, fp_size
                    )
                    to_do_map[future] = file

            for future in as_completed(to_do_map):
                file = to_do_map[future]
                fingerprint = future.result()
                if fingerprint:
                    fingerprints[file] = fingerprint
    else:
        for root, _, files in os.walk(binary):
            for file in files:
                sample = os.path.join(root, file)
                fingerprint = process_sample(sample, shred_size, window_size, fp_size)
                if fingerprint:
                    fingerprints[file] = fingerprint

    pickle.dump(fingerprints, open(os.path.join(db, FINGERPRINT_DB), 'wb'))

    elapsed_time = perf_counter() - start_time
    logging.info('--------------- Updating Database ---------------')
    logging.info(f'Processed files : {len(fingerprints)}')
    logging.info(f'Time            : {elapsed_time // 60:.0f}min{elapsed_time % 60:.3f}sec')


def process_sample(
    sample: str, shred_size: int, window_size: int, fp_size: int
) -> Fingerprint | None:
    binary_file = initailaize_binary_file(sample)
    if not binary_file:
        return None

    logging.debug(binary_file)
    shred_hashes = shred_section(binary_file, shred_size)

    if len(shred_hashes) < window_size:
        logging.warning(
            f'{sample} skipped (no appropriate sections): {len(shred_hashes)=}, {window_size=}'
        )
        return None

    fingerprint = create_fingerprint(shred_hashes, fp_size, window_size)

    if (fp_set_bits := bit_count(fingerprint)) > fp_size * 1024 * 8 * MAX_SET_BITS_RATIO:
        logging.warning(
            f'{sample} skipped (too big to fit into the current fingerprint): {fp_set_bits=}, {fp_size=}'
        )
        return None

    return Fingerprint(fingerprint, fp_set_bits)


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
                if shred_hashes[i + j] <= min_hash:
                    min_hash = shred_hashes[i + j]
                    min_hash_idx = i + j
            bit_vector_set(bit_vector, min_hash & (fp_size_bits - 1))
        else:  # min_hash_idx is in current window
            if shred_hashes[i + window_size - 1] <= min_hash:
                min_hash = shred_hashes[i + window_size - 1]
                min_hash_idx = i + window_size - 1
                bit_vector_set(bit_vector, min_hash & (fp_size_bits - 1))

    return bit_vector


def shred_section(binary_file: BinaryFile, shred_size: int) -> list[int]:
    logging.debug(f'Shredding {binary_file.filename}')

    shred_hashes = []
    for section in binary_file.sections:
        if (
            not section.is_code
            or not (section.vma <= binary_file.start_addr <= section.vma + section.data_size)
            and section.name not in ('.text', 'CODE')
        ):
            logging.debug(f'Skipping section {section.name}: {section}')
            continue

        if section.data_size < shred_size:
            logging.warning(
                f'Invalid size for section {section.name}: {section.data_size=}, {shred_size=}'
            )
            continue

        logging.debug(f'Processing section {section.name}: {section.data_size=}, {shred_size=}')

        section_shred_num = section.data_size - shred_size + 1
        for i in range(section_shred_num):
            shred = section.data[i : i + shred_size]
            shred_hash = djb2_hash(shred)
            shred_hashes.append(shred_hash)

        logging.debug(f'Finished processing section {section.name}')

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


def jaccard_distance(fp_a: Fingerprint, fp_b: Fingerprint) -> float:
    byteorder = 'little'
    fp_a_bit_vector = int.from_bytes(fp_a.bit_vector, byteorder=byteorder)
    fp_b_bit_vector = int.from_bytes(fp_b.bit_vector, byteorder=byteorder)
    bit_vector_intersection = (fp_a_bit_vector & fp_b_bit_vector).bit_count()

    bit_vector_union = fp_a.bit_count + fp_b.bit_count - bit_vector_intersection

    return bit_vector_intersection / bit_vector_union


def bit_count(fingerprint: bytearray) -> int:
    return sum(byte.bit_count() for byte in fingerprint)
