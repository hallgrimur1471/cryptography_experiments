import drvn.cryptography.utils as utils
import drvn.cryptography.sha as sha


def sha1(key, message):
    """
    HMAC-SHA1
    """
    return hmac(key, message, sha.sha1, 64)


def hmac(key, message, hash_, blockSize):
    """
    Generic HMAC.

    Args:
        key (bytes)
        message (bytes)
        hash (function):
            The hash function to use (.e.g SHA-1)
        blockSize (int):
            The block size of the hash function (e.g. 64 bytes for SHA-1)
    """
    # Keys longer than blockSize are shortened by hashing them
    if len(key) > blockSize:
        key = hash(key)
    else:
        # Keys shorter than blockSize are padded to blockSize
        # by padding with zeros on the right
        key = key + (b"\x00" * (blockSize - len(key)))

    o_key_pad = utils.fixed_xor(
        key, (0x5C).to_bytes(1, byteorder="little") * blockSize
    )  # Outer padded key
    i_key_pad = utils.fixed_xor(
        key, (0x36).to_bytes(1, byteorder="little") * blockSize
    )  # Inner padded key

    return hash_(o_key_pad + hash_(i_key_pad + message))
