import os
import argparse
from dataclasses import dataclass, field
import pickle
import logging

from functools import total_ordering 
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG, filename='bitshred.log', filemode='w')

import pefile

@total_ordering
class Address:
    """Address class prints the memory address in hex format in repr"""

    def __init__(self, address: int) -> None:
        self.address = address

    def __repr__(self) -> str:
        return hex(self.address)
    
    def __add__(self, other: 'Address | int') -> 'Address':
        try:
            return Address(self.address + other.address)
        except AttributeError:
            logging.debug(f'Other is not an Address object')

        try:
            return Address(self.address + int(other))
        except ValueError:
            logging.debug(f'Other is also not an integer')
            raise

    def __eq__(self, other: 'Address') -> bool:
        return self.address == other.addressss
    
    def __lt__(self, other: 'Address') -> bool:
        return self.address < other.address

@dataclass
class Section:
    name: str
    data: bytes = field(repr=False)
    data_size: int
    vma: Address
    is_code: bool

@dataclass
class BinaryFile:
    filename: str
    file_size: int
    start_addr: Address
    sections: list[Section]

def main(args: argparse.Namespace):
    fingerprints: dict[str, bytearray] = {}
    for root, _, files in os.walk(args.binary):
        for file in files:
            sample = os.path.join(root, file)

            binary_file = initailaize_binary_file(sample)
            if not binary_file:
                continue
            
            logging.debug(binary_file)
            shred_hashes = shred_section(binary_file, args.shred_size)

            if len(shred_hashes) < args.window_size:
                logging.warning(f'{sample} skipped (no appropriate sections)')
                continue

            fingerprint = create_fingerprint(shred_hashes, args.fp_size, args.window_size)
            fingerprints[sample] = fingerprint

    pickle.dump(fingerprints, open('fingerprints.pkl', 'wb'))

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

def bit_vector_set(vector: bytearray, offset: int) -> None:
    byte_index = offset >> 3
    bit_mask = 1 << (offset & 0x7)
    vector[byte_index] |= bit_mask


def initailaize_binary_file(file_path: str) -> BinaryFile:
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        logging.warning(f'{file_path} is not a PE file')
        return

    pefile_metadata = {
        'filename': os.path.basename(file_path),
        'file_size': os.path.getsize(file_path),
        'start_addr': Address(
            pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ),
    }

    sections_data = [
        Section(
            name=section.Name.decode().rstrip('\x00'),
            data=section.get_data(),
            # TODO: should we use SizeOfRawData or Misc_VirtualSize?
            data_size=section.SizeOfRawData,
            vma=Address(pe.OPTIONAL_HEADER.ImageBase+section.VirtualAddress),
            is_code=section.IMAGE_SCN_CNT_CODE
        ) for section in pe.sections
    ]

    return BinaryFile(
        **pefile_metadata,
        sections=sections_data
    )

def shred_section(binary_file: BinaryFile, shred_size: int) -> list[int]:
    logging.debug(f'Shredding {binary_file.filename}')

    shred_hashes = []
    for section in binary_file.sections:
        if (
            not section.is_code or
            not (section.vma <= binary_file.start_addr <= section.vma + section.data_size) or
            section.name not in ('.text', 'CODE')
        ):
            logging.debug(f'Skipping section {section.name}')
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


def djb2_hash(data: bytes) -> int:
    hash = 5381
    for byte in data:
        hash = hash * 33 + byte
    # limits the hash to 32 bits (unsigned int)
    return hash & 0xFFFFFFFF


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BitShred reimplementation in Python')
    parser.add_argument('-b', '--binary', help='Path to directory that contains binary samples')
    parser.add_argument('-s', '--shred-size', help='Shred size', default=4, type=int)
    parser.add_argument('-w', '--window-size', help='Window size', default=1, type=int)
    parser.add_argument('--fp-size', help='Fingerprint size (in KB)', default=32, type=int)
    args = parser.parse_args()
    main(args)