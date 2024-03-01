import json
import logging
import os
import pickle
import reprlib
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from itertools import combinations
from time import perf_counter
from typing import Callable

from binary_file import BinaryFile, initailaize_binary_file
from fingerprint import Fingerprint, create_fingerprint, fingerprint_encoder, jaccard_distance
from utils import djb2_hash

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
DEBUG = os.getenv('DEBUG', '').lower() in ('true', '1')
MULTIPROCESSING = not DEBUG


def update_fingerprint_db(
    binary: str, raw: str, shred_size: int, window_size: int, fp_size: int, db: str, all_sec: bool
) -> None:
    """
    Compute the fingerprints of all the samples in either `binary` or `raw` directory depending on the settings
    and store the results in `fingerprints.pkl`
    """
    # for performance measurement
    start_time: float = perf_counter()

    if binary:
        fingerprints = _update_with_executables(binary, shred_size, window_size, fp_size, all_sec)
    elif raw:
        fingerprints = _update_with_raw_files(raw, shred_size, window_size, fp_size)
    else:
        error_message = 'Either binary or raw directory must be specified'
        logging.error(error_message)
        raise ValueError(error_message)

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


def _update_with_executables(
    binary: str, shred_size: int, window_size: int, fp_size: int, all_sec: bool
) -> dict[str, Fingerprint]:
    """
    Compute the fingerprints of all the samples in `binary` directory
    """
    return _update_runner(
        processor=process_executable,
        sample_dir=binary,
        shred_size=shred_size,
        window_size=window_size,
        fp_size=fp_size,
        all_sec=all_sec,
    )


def _update_with_raw_files(
    raw: str, shred_size: int, window_size: int, fp_size: int
) -> dict[str, Fingerprint]:
    """
    Compute the fingerprints of all the samples in `raw` directory
    """
    return _update_runner(
        processor=process_raw_file,
        sample_dir=raw,
        shred_size=shred_size,
        window_size=window_size,
        fp_size=fp_size,
    )


def _update_runner(processor: Callable, sample_dir: str, **kwargs) -> dict[str, Fingerprint]:
    """
    Compute the fingerprints of all the samples in `sample_dir`
    """
    fingerprints: dict[str, Fingerprint] = {}
    max_workers = os.cpu_count() if MULTIPROCESSING else 1
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        to_do_map = {}
        for root, _, files in os.walk(sample_dir):
            for file in files:
                sample = os.path.join(root, file)
                future = executor.submit(processor, sample, **kwargs)
                to_do_map[future] = file

        for future in as_completed(to_do_map):
            file = to_do_map[future]
            fingerprint = future.result()
            if fingerprint:
                fingerprints[file] = fingerprint

    return fingerprints


def compare_fingerprint_db(db: str) -> None:
    """
    Compare the fingerprints of all the samples in `fingerprints.pkl` pairwise using Jaccard distance
    and store the results in `jaccard.pkl`
    """
    # for performance measurement
    start_time: float = perf_counter()

    fingerprints = pickle.load(open(os.path.join(db, FINGERPRINT_DB), 'rb'))
    jaccard_distances: dict[frozenset[str], float] = {}
    max_workers = os.cpu_count()//2 if MULTIPROCESSING else 1
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        to_do_map = {}

        n_fingerprints = len(fingerprints)
        n_comparisons = n_fingerprints * (n_fingerprints - 1) // 2
        batch_size = max(100, n_comparisons // (max_workers * 10 * 1000))
        # cannot materialize all the pairs since it will take too much memory
        all_pairs = combinations(fingerprints.keys(), 2)

        logging.debug(
            f'{n_comparisons} comparisons to be done, {batch_size} per batch, {max_workers} workers'
        )

        # submit every comparision to the executor would create too many tasks
        # so we submit them in batches
        while True:
            # return None if there is no more pair
            batch = list(next(all_pairs, None) for _ in range(batch_size))

            # break if no more pairs
            if not any(batch):
                break

            future = executor.submit(_compare_batch_runner, batch, fingerprints)
            to_do_map[future] = batch

        for i, future in enumerate(as_completed(to_do_map)):
            jaccard_distances: dict[frozenset[str], float] = {}
            batch_results = future.result()
            for file_a, file_b, similarity in batch_results:
                jaccard_distances[frozenset({file_a, file_b})] = similarity
            pickle.dump(jaccard_distances, open(os.path.join(db, f'{JACCARD_BASE}_{i+1}.pkl'), 'wb'))
            # more than 2GB+ of data will be produced if we have 6000+ samples
            # so we only dump the json file if we are in debug mode
            if DEBUG:
                json.dump(
                    {reprlib.repr(k): v for k, v in jaccard_distances.items()},
                    open(os.path.join(db, f'{JACCARD_BASE}_{i+1}.pkl'), 'w'),
                    indent=4,
                )

    elapsed_time = perf_counter() - start_time
    logging.info('--------------- Comparing Database ---------------')
    logging.info(f'# of viruses : {len(fingerprints)}')
    logging.info(f'Time         : {elapsed_time // 60:.0f}min{elapsed_time % 60:.3f}sec')

def efficient_compare_fingerprint_db(db: str) -> None:
    """
    Compare the fingerprints of all the samples in `fingerprints.pkl` pairwise using Jaccard distance
    and store the results in `jaccard.pkl`
    """
    # for performance measurement
    start_time: float = perf_counter()

    fingerprints = pickle.load(open(os.path.join(db, FINGERPRINT_DB), 'rb'))
    jaccard_distances: dict[frozenset[str], float] = {}
    max_workers = os.cpu_count()//2 if MULTIPROCESSING else 1
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        to_do_map = []

        n_fingerprints = len(fingerprints)
        n_comparisons = n_fingerprints * (n_fingerprints - 1) // 2
        batch_size = max(100, n_comparisons // (max_workers * 10 * 1000))
        # cannot materialize all the pairs since it will take too much memory
        all_pairs = combinations(fingerprints.keys(), 2)

        logging.debug(
            f'{n_comparisons} comparisons to be done, {batch_size} per batch, {max_workers} workers'
        )

        # submit every comparision to the executor would create too many tasks
        # so we submit them in batches
        while True:
            # return None if there is no more pair
            batch = list(next(all_pairs, None) for _ in range(batch_size))

            # break if no more pairs
            if not any(batch):
                break
            
            batch_pairs=[]
            for a, b in batch:
                batch_pairs.append((a,b,fingerprints[a], fingerprints[b]))

            future = executor.submit(_efficient_compare_batch_runner, batch_pairs)
            to_do_map.append(future)

        for i, future in enumerate(as_completed(to_do_map)):
            jaccard_distances: dict[frozenset[str], float] = {}
            batch_results = future.result()
            for file_a, file_b, similarity in batch_results:
                jaccard_distances[frozenset({file_a, file_b})] = similarity
            pickle.dump(jaccard_distances, open(os.path.join(db, f'{JACCARD_BASE}_{i+1}.pkl'), 'wb'))
            # more than 2GB+ of data will be produced if we have 6000+ samples
            # so we only dump the json file if we are in debug mode
            if DEBUG:
                json.dump(
                    {reprlib.repr(k): v for k, v in jaccard_distances.items()},
                    open(os.path.join(db, f'{JACCARD_BASE}_{i+1}.pkl'), 'w'),
                    indent=4,
                )

    elapsed_time = perf_counter() - start_time
    logging.info('--------------- Comparing Database ---------------')
    logging.info(f'# of viruses : {len(fingerprints)}')
    logging.info(f'Time         : {elapsed_time // 60:.0f}min{elapsed_time % 60:.3f}sec')


def _compare_batch_runner(
    batch: list[tuple[str, str]], fingerprints: dict[str, Fingerprint]
) -> list[tuple[str, str, float]]:
    results = []
    for pair in batch:
        if pair is None:
            break

        file_a, file_b = pair
        similarity = jaccard_distance(fingerprints[file_a], fingerprints[file_b])
        results.append((file_a, file_b, similarity))

        if DEBUG:
            logging.debug(f'{file_a} vs {file_b}: {similarity=}')

    return results

def _efficient_compare_batch_runner(batch: list[tuple[str, str, Fingerprint, Fingerprint]]) -> list[tuple[str, str, float]]:
    results = []
    for pair in batch:
        if pair is None:
            break
        file_a, file_b, f_a, f_b=pair
        similarity = jaccard_distance(f_a, f_b)
        results.append((file_a, file_b, similarity))

        if DEBUG:
            logging.debug(f'{file_a} vs {file_b}: {similarity=}')

    return results


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


def process_executable(
    sample: str, shred_size: int, window_size: int, fp_size: int, all_sec: bool
) -> Fingerprint | None:
    binary_file = initailaize_binary_file(sample)
    if not binary_file:
        return None

    logging.debug(binary_file)
    shred_hashes = shred_section(binary_file, shred_size, all_sec)

    if len(shred_hashes) < window_size:
        logging.warning(
            f'{sample} skipped (no appropriate sections): {len(shred_hashes)=}, {window_size=}'
        )
        return None

    fingerprint = create_fingerprint(shred_hashes, fp_size, window_size)
    if fingerprint.bit_count > fp_size * 1024 * 8 * MAX_SET_BITS_RATIO:
        logging.warning(
            f'{sample} skipped (too big to fit into the current fingerprint): {fingerprint.bit_count=}, {fp_size=}'
        )
        return None

    logging.debug(
        f'{sample} fingerprint created sucessfully: {fingerprint.bit_count} bits set in fingerprint'
    )

    return fingerprint


def process_raw_file(
    sample: str, shred_size: int, window_size: int, fp_size: int
) -> Fingerprint | None:
    with open(sample, 'rb') as f:
        data = f.read()

    logging.debug(f'{sample=}, {len(data)=}')

    shred_hashes = []
    for i in range(len(data) - shred_size + 1):
        shred = data[i : i + shred_size]
        shred_hash = djb2_hash(shred)
        shred_hashes.append(shred_hash)

    fingerprint = create_fingerprint(shred_hashes, fp_size, window_size)
    if fingerprint.bit_count > fp_size * 1024 * 8 * MAX_SET_BITS_RATIO:
        logging.warning(
            f'{sample} skipped (too big to fit into the current fingerprint): {fingerprint.bit_count=}, {fp_size=}'
        )
        return None

    logging.debug(
        f'{sample} fingerprint created sucessfully: {fingerprint.bit_count} bits set in fingerprint'
    )

    return fingerprint


def shred_section(binary_file: BinaryFile, shred_size: int, all_sec: bool) -> list[int]:
    logging.debug(f'Shredding {binary_file.filename}')

    shred_hashes = []
    for section in binary_file.sections:
        if (
            # process the executable section located at entry point
            (
                not section.is_code
                or not (section.vma <= binary_file.start_addr <= section.vma + section.data_size)
            )
            # process the section whose name is .text or CODE
            and section.name not in ('.text', 'CODE')
            # process all sections if the all_sec flag is set
            and not all_sec
        ):
            logging.debug(f'({binary_file.filename}) Skipping section {section.name}: {section}')
            continue

        if section.data_size < shred_size:
            logging.warning(
                f'({binary_file.filename}) Invalid size for section {section.name}: {section.data_size=}, {shred_size=}'
            )
            continue

        logging.debug(
            f'({binary_file.filename}) Processing section {section.name}: {section.data_size=}, {shred_size=}'
        )

        section_shred_num = section.data_size - shred_size + 1
        for i in range(section_shred_num):
            shred = section.data[i : i + shred_size]
            shred_hash = djb2_hash(shred)
            shred_hashes.append(shred_hash)

        logging.debug(f'({binary_file.filename}) Finished processing section {section.name}')

    logging.debug(f'{len(shred_hashes)=}')
    return shred_hashes
