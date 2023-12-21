import logging
import os
from dataclasses import dataclass, field
from functools import total_ordering

import pefile  # type: ignore


@total_ordering
class Address:
    """Address class prints the memory address in hex format in repr"""

    def __init__(self, address: int) -> None:
        self.address = address

    def __repr__(self) -> str:
        return hex(self.address)

    def __add__(self, other: 'Address | int') -> 'Address':
        if isinstance(other, Address):
            return Address(self.address + other.address)
        elif isinstance(other, int):
            return Address(self.address + other)
        else:
            error_msg = f'Unsupported type for addition: {type(other)}'
            logging.error(error_msg)
            raise TypeError(error_msg)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Address):
            return NotImplemented
        return self.address == other.address

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


def initailaize_binary_file(file_path: str) -> BinaryFile | None:
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        logging.warning(f'{file_path} is not a PE file')
        return None

    sections_data = [
        Section(
            name=section.Name.decode().rstrip('\x00'),
            data=section.get_data(),
            # TODO: should we use SizeOfRawData or Misc_VirtualSize?
            data_size=section.SizeOfRawData,
            vma=Address(pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress),
            is_code=section.IMAGE_SCN_CNT_CODE or section.IMAGE_SCN_MEM_EXECUTE,
        )
        for section in pe.sections
    ]

    return BinaryFile(
        filename=os.path.basename(file_path),
        file_size=os.path.getsize(file_path),
        start_addr=Address(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        sections=sections_data,
    )
