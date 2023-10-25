import os
import argparse
from dataclasses import dataclass, field
import logging

from functools import total_ordering 
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)

import pefile

@total_ordering
@dataclass
class Address:
    address: int

    def __repr__(self):
        return hex(self.address)
    
    def __add__(self, other):
        try:
            return Address(self.address + other.address)
        except AttributeError:
            logging.debug(f'Other is not an Address object')

        try:
            return Address(self.address + int(other))
        except ValueError:
            logging.debug(f'Other is also not an integer')
            raise
    
    def __lt__(self, other):
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
    for root, _, files in os.walk(args.binary):
        for file in files:
            sample = os.path.join(root, file)
            binary_file = initailaize_binary_file(sample)
            if binary_file:
                shred_section(binary_file, args.shred_size)

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
            data_size=section.SizeOfRawData,
            vma=Address(pe.OPTIONAL_HEADER.ImageBase+section.VirtualAddress),
            is_code=section.IMAGE_SCN_CNT_CODE
        ) for section in pe.sections
    ]

    return BinaryFile(
        **pefile_metadata,
        sections=sections_data
    )

def shred_section(binary_file: BinaryFile, shred_size: int):
    logging.debug(f'Shredding {binary_file.filename}')
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




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BitShred reimplementation in Python')
    parser.add_argument('-b', '--binary', help='Path to directory that contains binary samples')
    parser.add_argument('-s', '--shred-size', help='Shred size', default=4, type=int)
    args = parser.parse_args()
    main(args)