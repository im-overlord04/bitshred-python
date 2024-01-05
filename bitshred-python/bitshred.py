import argparse
import logging

from fingerprint_db import cluster_fingerprint_db, compare_fingerprint_db, update_fingerprint_db

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)


def main(args: argparse.Namespace) -> None:
    if args.binary:
        update_fingerprint_db(
            binary=args.binary,
            shred_size=args.shred_size,
            window_size=args.window_size,
            fp_size=args.fp_size,
            db=args.db,
            data_sec=args.data_sec
        )
    elif args.compare:
        compare_fingerprint_db(args.db)
    elif args.cluster:
        cluster_fingerprint_db(args.db, args.jacard)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BitShred reimplementation in Python')

    execution_mode = parser.add_mutually_exclusive_group(required=True)
    execution_mode.add_argument(
        '-b',
        '--binary',
        help='Update database by processing binary files (PE files), add path to directory containing binary files after this option',
        default=None,
    )
    execution_mode.add_argument(
        '-a',
        '--raw',
        help='Update database by processing raw binary files, add path to directory containing raw binary files after this option',
        default=None
    )
    execution_mode.add_argument(
        '-p', '--compare', action='store_true', help='Compare samples in database'
    )
    execution_mode.add_argument(
        '-r', '--cluster', action='store_true', help='Cluster samples in database'
    )

    parser.add_argument('-s', '--shred-size', help='Shred size', default=12, type=int)
    parser.add_argument('-w', '--window-size', help='Window size', default=16, type=int)
    parser.add_argument('--fp-size', help='Fingerprint size (in KB)', default=32, type=int)
    parser.add_argument('-d', '--db', help='Set database path', default='.', type=str)
    parser.add_argument('--data-sec', help='Include .data section in the shreding process', action='store_true')
    parser.add_argument('-j', '--jacard', help='Set Jaccard threshold', default=0.6, type=float)

    args = parser.parse_args()

    main(args)
