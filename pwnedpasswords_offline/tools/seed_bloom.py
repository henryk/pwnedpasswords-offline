from pathlib import Path
from time import time

from pwnedpasswords_offline.bloom import PwnedBloomFilter

DATA_FILE_NAME = "data/pwned-passwords-sha1-ordered-by-hash-v7.txt"
BLOOM_FILE_NAME = "data/pwned-passwords-sha1-ordered-by-hash-v7.bloom"


def main():
    start = time()
    lap = start
    total_count = 0
    count = 0
    add_count = 0

    with open(DATA_FILE_NAME, "rb") as fp:
        with PwnedBloomFilter(Path(BLOOM_FILE_NAME)) as bf:
            for line in fp:
                if add_count > 20:
                    count += add_count
                    add_count = 0

                    if time() - lap > 30:
                        print("Current rate:", count / (time() - lap), "per second")
                        lap = time()
                        count = 0

                bf.add(line[0:40])

                count += 1
                add_count += 1

    stop = time()

    diff = stop - start
    ops_per_sec = total_count / diff

    print(f"Took {diff}s, {ops_per_sec} per sec")


if __name__ == "__main__":
    main()
