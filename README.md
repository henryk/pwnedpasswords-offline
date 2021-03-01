# Pwned Passwords check (offline)

![PyPI](https://img.shields.io/pypi/v/pwnedpasswords-offline)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Features

 * Check passwords or plain SHA-1 hashes against haveibeenpwned password list
 * Fully offline operation, needs to be provided with external database file (~25 GB)
 * Optional [Bloom filter](https://en.wikipedia.org/wiki/Bloom_filter) to speed up common (negative) case

## Quickstart

* Download "SHA-1" version "(ordered by hash)" from https://haveibeenpwned.com/Passwords
* Extract file, yielding `pwned-passwords-sha1-ordered-by-hash-v7.txt` (for current version 7), put into `data` directory under current directory
* Install with `pip install pwnedpasswords_offline`
* Optional: Seed Bloom filter: `pwnedpasswords_offline_seed_bloom`, takes about 45min to run, will generate a 512MiB file

## Speed

(Results approximate, measured on my personal laptop)

|                        | w/o Bloom filter | w/ Bloom filter |
|------------------------|-----------------:|----------------:|
| Positive match (pwned) |         61 us/op |       198 us/op |
| Negative match         |        121 us/op |        14 us/op |
| Average @ 1% positive  |         64 us/op |        16 us/op |

These results were measured with batch operation at 20000 items. One-shot operation will be much slower due to the overhead of opening data files.

The data files are opened with mmap(2), and accessed in random order. No explicit non-garbage-collected Python objects are generated during operation, so it should be safe to open the data files once at the start of your application and then keep them open until your process ends. Note: The memory mapping will not survive a fork(2), so you cannot use a pre-forking webserver such as gunicorn to only open the data files once. Each process needs to open its own copy. 

## Simple usage
````python
from pwnedpasswords_offline import PwnedPasswordsOfflineChecker
if PwnedPasswordsOfflineChecker("data/pwned-passwords-sha1-ordered-by-hash-v7.txt").lookup_raw_password("Password1!"):
    print("Pwned!")
````

## Batch usage
You can also pre-open the database file, especially if you're checking multiple passwords in bulk:

````python
from pwnedpasswords_offline import PwnedPasswordsOfflineChecker
checker = PwnedPasswordsOfflineChecker("data/pwned-passwords-sha1-ordered-by-hash-v7.txt")
checker.open()
for password in ["Password1!", "correct horse battery staple", "actress stapling driver placidly swivel doorknob"]:
    if checker.lookup_raw_password(password):
        print(f"'{password}' is pwned!")
checker.close()
````

You should not forget to call `.close()` after you're done.

## As context manager

You can use the object as a context manager to automatically open and close it:

`````python
from pwnedpasswords_offline import PwnedPasswordsOfflineChecker
with PwnedPasswordsOfflineChecker("data/pwned-passwords-sha1-ordered-by-hash-v7.txt") as checker:
    for password in ["Password1!", "correct horse battery staple", "actress stapling driver placidly swivel doorknob"]:
        if checker.lookup_raw_password(password):
            print(f"'{password}' is pwned!")
`````

## Check hash directly

Instead of calling `.lookup_raw_password()` you can call `.lookup_hash()` if you already have the plain SHA-1 hash:

````python
from pwnedpasswords_offline import PwnedPasswordsOfflineChecker
if PwnedPasswordsOfflineChecker("data/pwned-passwords-sha1-ordered-by-hash-v7.txt").lookup_hash("32CA9FD4B3F319419F2EA6F883BF45686089498D"):
    print("Pwned!")
````
