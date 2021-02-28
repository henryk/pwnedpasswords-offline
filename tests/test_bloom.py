from pwnedpasswords_offline.bloom import PwnedBloomFilter


def test_bloom_1(tmp_path):
    with PwnedBloomFilter(tmp_path / "test.bloom") as bf:
        bf.add(b"1")
        bf.add(b"2")

        assert bf.contains(b"1")
        assert bf.contains(b"2")
        assert not bf.contains(b"3")
