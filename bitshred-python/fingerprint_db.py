import json
import logging
import os
import pickle
import reprlib
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from itertools import combinations
from time import perf_counter
from typing import Literal

from binary_file import BinaryFile, initailaize_binary_file

FINGERPRINT_BASE = 'fingerprints'
JACCARD_BASE = 'jaccard'
CLUSTER_BASE = 'cluster'

FINGERPRINT_DB = f'{FINGERPRINT_BASE}.pkl'
JACCARD_DB = f'{JACCARD_BASE}.pkl'
CLUSTER_DB = f'{CLUSTER_BASE}.pkl'

# JSON files for human-readable output
FINGERPRINT_JSON = f'{FINGERPRINT_BASE}.json'
JACCARD_JSON = f'{JACCARD_BASE}.json'
CLUSTER_JSON = f'{CLUSTER_BASE}.json'

MAX_SET_BITS_RATIO = 0.7
MULTIPROCESSING = True


@dataclass
class Fingerprint:
    bit_vector: bytearray
    bit_count: int


def fingerprint_encoder(fingerprint: Fingerprint) -> dict[str, str | int]:
    return {
        'bit_vector': reprlib.repr(fingerprint.bit_vector.hex()),
        'bit_count': fingerprint.bit_count,
    }


def update_fingerprint_db(
    binary: str, shred_size: int, window_size: int, fp_size: int, db: str, data_sec: bool
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
                        process_sample, sample, shred_size, window_size, fp_size, data_sec
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
                fingerprint = process_sample(sample, shred_size, window_size, fp_size, data_sec)
                if fingerprint:
                    fingerprints[file] = fingerprint

    pickle.dump(fingerprints, open(os.path.join(db, FINGERPRINT_DB), 'wb'))
    json.dump(
        fingerprints,
        open(os.path.join(db, FINGERPRINT_JSON), 'w'),
        default=fingerprint_encoder,
        indent=4,
    )

    elapsed_time = perf_counter() - start_time
    logging.info('--------------- Updating Database ---------------')
    logging.info(f'Processed files : {len(fingerprints)}')
    logging.info(f'Time            : {elapsed_time // 60:.0f}min{elapsed_time % 60:.3f}sec')

def _update_with_executables():
    pass

def _update_with_raw_files():
    pass


def compare_fingerprint_db(db: str) -> None:
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
                jaccard_distances[frozenset({file_a, file_b})] = similarity
                logging.debug(f'{file_a} vs {file_b}: {similarity=}')
    else:
        for file_a, file_b in combinations(fingerprints.keys(), 2):
            similarity = jaccard_distance(fingerprints[file_a], fingerprints[file_b])
            jaccard_distances[frozenset({file_a, file_b})] = similarity
            logging.debug(f'{file_a} vs {file_b}: {similarity=}')

    pickle.dump(jaccard_distances, open(os.path.join(db, JACCARD_DB), 'wb'))
    json.dump(
        {reprlib.repr(k): v for k, v in jaccard_distances.items()},
        open(os.path.join(db, JACCARD_JSON), 'w'),
        indent=4,
    )

    elapsed_time = perf_counter() - start_time
    logging.info('--------------- Comparing Database ---------------')
    logging.info(f'# of viruses : {len(fingerprints)}')
    logging.info(f'Time         : {elapsed_time // 60:.0f}min{elapsed_time % 60:.3f}sec')


def cluster_fingerprint_db(db: str, jacard_threshold: float) -> None:
    """
    Cluster the samples in `fingerprints.pkl` using Jaccard distance stored in `jaccard.pkl`
    and store the results in `cluster.pkl`
    """
    # for performance measurement
    start_time: float = perf_counter()

    # initialize cluster assignment, (key, value) = (sample, cluster ID)
    # 0 means the sample is not assigned to any cluster yet
    fingerprints = pickle.load(open(os.path.join(db, FINGERPRINT_DB), 'rb'))
    cluster_assignment: dict[str, int] = {}
    for sample in fingerprints.keys():
        cluster_assignment[sample] = 0

    # assign each sample to a cluster ID, cluster ID starts from 1
    jaccard_distances = pickle.load(open(os.path.join(db, JACCARD_DB), 'rb'))
    cluster_id = 1
    for pair, similarity in jaccard_distances.items():
        sample_a, sample_b = pair
        if similarity >= jacard_threshold:
            # both samples are not assigned to any cluster yet
            if cluster_assignment[sample_a] == 0 and cluster_assignment[sample_b] == 0:
                cluster_assignment[sample_a] = cluster_id
                cluster_assignment[sample_b] = cluster_id
                cluster_id += 1
            # sample_a is not assigned to any cluster yet
            elif cluster_assignment[sample_a] == 0:
                cluster_assignment[sample_a] = cluster_assignment[sample_b]
            # sample_b is not assigned to any cluster yet
            elif cluster_assignment[sample_b] == 0:
                cluster_assignment[sample_b] = cluster_assignment[sample_a]
            # both samples are assigned to some clusters
            else:
                cluster_a = cluster_assignment[sample_a]
                cluster_b = cluster_assignment[sample_b]

                if cluster_a == cluster_b:
                    continue

                for sample, cluster in cluster_assignment.items():
                    if cluster == cluster_b:
                        cluster_assignment[sample] = cluster_a

    clusters: defaultdict[int, list[str]] = defaultdict(list)
    for sample, cluster_id in cluster_assignment.items():
        clusters[cluster_id].append(sample)

    # place samples in cluster 0 (samples that do not belong to any cluster) to their own cluster
    cluster_id = len(clusters)
    for sample in clusters[0]:
        clusters[cluster_id].append(sample)
        cluster_id += 1
    del clusters[0]

    pickle.dump(dict(clusters), open(os.path.join(db, CLUSTER_DB), 'wb'))
    json.dump(dict(clusters), open(os.path.join(db, CLUSTER_JSON), 'w'), indent=4)

    elapsed_time = perf_counter() - start_time
    logging.info('--------------- Clustering Database ---------------')
    logging.info(f'Jacard threshold : {jacard_threshold}')
    logging.info(f'# of clusters    : {len(clusters)}')
    logging.info(f'Time             : {elapsed_time // 60:.0f}min{elapsed_time % 60:.3f}sec')


def process_sample(
    sample: str, shred_size: int, window_size: int, fp_size: int, data_sec: bool
) -> Fingerprint | None:
    binary_file = initailaize_binary_file(sample)
    if not binary_file:
        return None

    logging.debug(binary_file)
    shred_hashes = shred_section(binary_file, shred_size, data_sec)

    if len(shred_hashes) < window_size:
        logging.warning(
            f'{sample} skipped (no appropriate sections): {len(shred_hashes)=}, {window_size=}'
        )
        return None

    fingerprint = create_fingerprint(shred_hashes, fp_size, window_size)
    logging.debug(f'{bit_count(fingerprint)} bits set in fingerprint')

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


def shred_section(binary_file: BinaryFile, shred_size: int, data_sec: bool) -> list[int]:
    logging.debug(f'Shredding {binary_file.filename}')

    shred_hashes = []
    for section in binary_file.sections:
        # only process the executable section located at entry point whose name is .text or CODE
        # and the .data section if the data_sec flag is set
        if (
            (
                not section.is_code
                or not (section.vma <= binary_file.start_addr <= section.vma + section.data_size)
            )
            and section.name not in ('.text', 'CODE')
            and not (data_sec and section.name == '.data')
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

    logging.debug(f'{len(shred_hashes)=}')
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
    byteorder: Literal['little', 'big'] = 'little'
    fp_a_bit_vector = int.from_bytes(fp_a.bit_vector, byteorder=byteorder)
    fp_b_bit_vector = int.from_bytes(fp_b.bit_vector, byteorder=byteorder)
    bit_vector_intersection = (fp_a_bit_vector & fp_b_bit_vector).bit_count()

    bit_vector_union = fp_a.bit_count + fp_b.bit_count - bit_vector_intersection

    return bit_vector_intersection / bit_vector_union


def bit_count(fingerprint: bytearray) -> int:
    return sum(byte.bit_count() for byte in fingerprint)
