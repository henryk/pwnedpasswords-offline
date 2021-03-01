import os
import string
from collections import deque
from dataclasses import dataclass
from hashlib import sha1
from random import Random
from time import time

from pwnedpasswords_offline import PwnedPasswordsOfflineChecker

BASE_COUNT = 20000

OUTER_PRIMING_COUNT = 2
OUTER_LOOP_COUNT = 4
INNER_PRIMING_COUNT = 0
INNER_LOOP_COUNT = 3
DATA_FILE_NAME = "data/pwned-passwords-sha1-ordered-by-hash-v7.txt"


@dataclass(eq=True, frozen=True)
class Scenario:
    true_positive_count: int
    true_negative_count: int
    enable_bloom: bool


SCENARIOS = [
    Scenario(BASE_COUNT, 0, True),
    Scenario(0, BASE_COUNT, True),
    Scenario(BASE_COUNT, 0, False),
    Scenario(0, BASE_COUNT, False),
    Scenario(BASE_COUNT // 100, BASE_COUNT - BASE_COUNT // 100, True),
    Scenario(BASE_COUNT // 100, BASE_COUNT - BASE_COUNT // 100, False),
]


def inner_loop(work, extra_opts):
    with PwnedPasswordsOfflineChecker(DATA_FILE_NAME, **extra_opts) as checker:
        for item, expected in work:
            if bool(checker.lookup_hash(item)) != expected:
                raise Exception("Internal error")


def outer_loop(scenario, seed=1234) -> float:
    r = Random(seed)
    true_positives = deque()
    true_negatives = deque()

    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits

    for i in range(scenario.true_negative_count):
        true_negatives.append(
            sha1("".join(r.choice(alphabet) for _ in range(25)).encode())
            .hexdigest()
            .upper()
            .encode()
        )

    with open(DATA_FILE_NAME, "rb") as fp:
        total_length = os.fstat(fp.fileno()).st_size
        if scenario.true_positive_count:
            average_skip = total_length // scenario.true_positive_count

        pos = 0

        for i in range(scenario.true_positive_count):
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

    if scenario.enable_bloom:
        extra_opts = {}
    else:
        extra_opts = {"bloom_file": None}

    for i in range(INNER_PRIMING_COUNT):
        inner_loop(mixed, extra_opts)

    start = time()
    for i in range(INNER_LOOP_COUNT):
        inner_loop(mixed, extra_opts)
    stop = time()

    diff = stop - start
    ops_per_sec = (len(mixed) * INNER_LOOP_COUNT) / diff

    return ops_per_sec


def main():
    results = {}

    for scenario in SCENARIOS:
        print("Running", scenario)
        results.setdefault(scenario, [])

        r = Random(1111)

        for i in range(OUTER_PRIMING_COUNT):
            outer_loop(scenario, seed=r.getrandbits(32))

        r = Random(2222)
        for i in range(OUTER_LOOP_COUNT):
            results[scenario].append(outer_loop(scenario, seed=r.getrandbits(32)))

        print("ops_per_sec:", results[scenario])

        mean_ops_per_sec = sum(results[scenario]) / len(results[scenario])
        mean_us_per_op = 1000000 / mean_ops_per_sec

        print(f"mean: {mean_ops_per_sec} ops/s, {mean_us_per_op} us/op")

    print("Overall results")
    import pprint

    pprint.pprint(results)


if __name__ == "__main__":
    main()
