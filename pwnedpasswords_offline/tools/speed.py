import os
import string
from collections import deque
from hashlib import sha1
from random import Random
from time import time

from pwnedpasswords_offline import PwnedPasswordsOfflineChecker

TRUE_POSITIVE_COUNT = 10000
TRUE_NEGATIVE_COUNT = TRUE_POSITIVE_COUNT
OUTER_PRIMING_COUNT = 2
OUTER_LOOP_COUNT = 4
INNER_PRIMING_COUNT = 0
INNER_LOOP_COUNT = 3
DATA_FILE_NAME = "data/pwned-passwords-sha1-ordered-by-hash-v7.txt"


def inner_loop(work):
    with PwnedPasswordsOfflineChecker(DATA_FILE_NAME) as checker:
        for item, expected in work:
            if bool(checker.lookup_hash(item)) != expected:
                raise Exception("Internal error")


def outer_loop(seed=1234) -> float:
    r = Random(seed)
    true_positives = deque()
    true_negatives = deque()

    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits

    for i in range(TRUE_NEGATIVE_COUNT):
        true_negatives.append(
            sha1("".join(r.choice(alphabet) for _ in range(25)).encode())
            .hexdigest()
            .upper()
            .encode()
        )

    with open(DATA_FILE_NAME, "rb") as fp:
        total_length = os.fstat(fp.fileno()).st_size
        average_skip = total_length // TRUE_POSITIVE_COUNT

        pos = 0

        for i in range(TRUE_POSITIVE_COUNT):
            pos += r.randint(44, average_skip * 2)
            pos = pos % total_length
            fp.seek(pos, 0)

            v = None
            while v not in [b"\x0d", b"\0xa"]:
                v = fp.read(1)
                if len(v) == 0:
                    break
                pos += 1

            while v in [b"\x0d", b"\0xa"]:
                v = fp.read(1)
                if len(v) == 0:
                    break
                pos += 1

            if len(v) == 0:
                break

            h = fp.read(40)
            true_positives.append(h)

    mixed = [(v, 0) for v in true_negatives] + [(v, 1) for v in true_positives]
    r.shuffle(mixed)

    for i in range(INNER_PRIMING_COUNT):
        inner_loop(mixed)

    start = time()
    for i in range(INNER_LOOP_COUNT):
        inner_loop(mixed)
    stop = time()

    diff = stop - start
    ops_per_sec = (len(mixed) * INNER_LOOP_COUNT) / diff

    return ops_per_sec


def main():
    results = []
    r = Random(1111)

    for i in range(OUTER_PRIMING_COUNT):
        outer_loop(r.getrandbits(32))

    r = Random(2222)
    for i in range(OUTER_LOOP_COUNT):
        results.append(outer_loop(r.getrandbits(32)))

    print("ops_per_sec:", results)

    mean_ops_per_sec = sum(results) / len(results)
    mean_us_per_op = 1000000 / mean_ops_per_sec

    print(f"mean: {mean_ops_per_sec} ops/s, {mean_us_per_op} us/op")


if __name__ == "__main__":
    main()
