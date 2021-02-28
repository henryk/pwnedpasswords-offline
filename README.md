# Pwned Passwords check (offline)

![PyPI](https://img.shields.io/pypi/v/pwnedpasswords-offline)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Quickstart

 * Download "SHA-1" version "(ordered by hash)" from https://haveibeenpwned.com/Passwords
 * Extract file, yielding `pwned-passwords-sha1-ordered-by-hash-v7.txt` (for current version 7)

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
