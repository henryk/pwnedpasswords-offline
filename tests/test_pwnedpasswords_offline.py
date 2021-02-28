from pathlib import Path

import pytest

from pwnedpasswords_offline import PwnedPasswordsOfflineChecker
from pwnedpasswords_offline.bloom import PwnedBloomFilter


@pytest.fixture
def data_file_path():
    return Path("tests/dummy_pwned-passwords-sha1-ordered-by-hash.txt")


def test_instantiation(data_file_path):
    a = PwnedPasswordsOfflineChecker(data_file_path)
    assert a


def test_instantiate_with_str(data_file_path):
    a = PwnedPasswordsOfflineChecker(str(data_file_path))
    assert a


def test_instantiate_with_dir(data_file_path):
    with pytest.raises(ValueError):
        PwnedPasswordsOfflineChecker(str(data_file_path.parent))


def test_instantiate_nonexist(data_file_path):
    with pytest.raises(ValueError):
        PwnedPasswordsOfflineChecker(data_file_path.parent / "foo.txt")


def test_open_close(data_file_path):
    a = PwnedPasswordsOfflineChecker(data_file_path)
    a.open()
    assert a._mh.is_open()
    a.close()


def test_context_1(data_file_path):
    a = PwnedPasswordsOfflineChecker(data_file_path)
    with a:
        assert a._mh.is_open()
    assert not a._mh.is_open()


def test_context_2(data_file_path):
    with PwnedPasswordsOfflineChecker(data_file_path) as a:
        assert a._mh.is_open()


def test_context_recursive_1(data_file_path):
    a = PwnedPasswordsOfflineChecker(data_file_path)
    with a:
        with a:
            assert a._mh.is_open()
        assert a._mh.is_open()
    assert not a._mh.is_open()


def test_lookup_1(data_file_path):
    with PwnedPasswordsOfflineChecker(data_file_path) as a:
        assert a.lookup_hash("0000005191D8BCB8B2DA0BC5B15294192B619367")


def test_lookup_2(data_file_path):
    with PwnedPasswordsOfflineChecker(data_file_path) as a:
        assert a.lookup_hash("0000005191d8bcb8b2da0bc5b15294192b619367")


def test_lookup_multiple(data_file_path):
    with PwnedPasswordsOfflineChecker(data_file_path) as a:
        assert a.lookup_hash("0000005191D8BCB8B2DA0BC5B15294192B619367")
        assert a.lookup_hash("00000060B05984C533F67B0B73DD5B9E4133A96E")


def test_lookup_direct(data_file_path):
    a = PwnedPasswordsOfflineChecker(data_file_path)
    assert a.lookup_hash("0000005191D8BCB8B2DA0BC5B15294192B619367")


def test_lookup_negative(data_file_path):
    a = PwnedPasswordsOfflineChecker(data_file_path)
    assert not a.lookup_hash("1000005191D8BCB8B2DA0BC5B15294192B619367")


def test_lookup_border_1(data_file_path):
    with PwnedPasswordsOfflineChecker(data_file_path) as a:
        assert a.lookup_hash("000000005AD76BD555C1D6D771DE417A4B87E4B4")


def test_lookup_border_2(data_file_path):
    with PwnedPasswordsOfflineChecker(data_file_path) as a:
        assert a.lookup_hash("32CA9FD4B3F319419F2EA6F883BF45686089498D")


def test_lookup_all(data_file_path):
    hash_lines = list(open(data_file_path, "rb").readlines())[:150]

    with PwnedPasswordsOfflineChecker(data_file_path) as a:
        for h in hash_lines:
            assert a.lookup_hash(h.split(b":")[0].strip())


def test_lookup_raw(data_file_path):
    with PwnedPasswordsOfflineChecker(data_file_path) as a:
        assert a.lookup_raw_password("Password1!")


def test_lookup_with_bloom(data_file_path, tmp_path):
    bloom_file = tmp_path / "test.bloom"
    with PwnedBloomFilter(bloom_file) as bf:
        bf.add("32CA9FD4B3F319419F2EA6F883BF45686089498D".encode())

    with PwnedPasswordsOfflineChecker(data_file_path, bloom_file=bloom_file) as a:
        assert a.lookup_hash("32CA9FD4B3F319419F2EA6F883BF45686089498D")
        assert a.lookup_hash("000000005AD76BD555C1D6D771DE417A4B87E4B4")

        assert not a.lookup_hash("BB" * 20)
