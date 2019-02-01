import argparse
import base64
import contextlib
import io
import json
import os
import socket
import struct
from typing import Callable
from typing import Dict
from typing import Generator
from typing import NamedTuple
from typing import Union

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SSH2_AGENTC_REQUEST_IDENTITIES = b'\x0b'  # bytes([11])
SSH2_AGENT_IDENTITIES_ANSWER = b'\x0c'  # bytes([12])
SSH2_AGENTC_SIGN_REQUEST = b'\x0d'  # bytes([13])
SSH2_AGENT_SIGN_RESPONSE = b'\x0e'  # bytes([14])

Readable = Union[socket.socket, io.BytesIO]


def read_bytes(sock: Readable, size: int) -> bytes:
    if size < 0:
        raise ValueError(f'Needs positive size: {size}')
    elif size == 0:
        return b''

    if isinstance(sock, io.BytesIO):
        read: Callable[[int], bytes] = sock.read
    else:
        read = sock.recv

    output = [read(size)]
    assert output[-1], 'unexpected EOF'
    size -= len(output[-1])
    while size > 0:
        output.append(read(size))
        assert output[-1], 'unexpected EOF'
        size -= len(output[-1])
    return b''.join(output)


def read_u32(sock: Readable) -> int:
    return struct.unpack('>L', read_bytes(sock, 4))[0]


def read_s(sock: Readable) -> bytes:
    return read_bytes(sock, read_u32(sock))


def encode_s(s: bytes) -> bytes:
    return struct.pack('>I', len(s)) + s


@contextlib.contextmanager
def should_exhaust(s: bytes) -> Generator[io.BytesIO, None, None]:
    with io.BytesIO(s) as bio:
        try:
            yield bio
        finally:
            if bio.read(1) != b'':
                raise ValueError('Expected EOF')


class Key(NamedTuple):
    contents: bytes
    comment: bytes

    def sign(self, sock: socket.socket, challenge: bytes) -> bytes:
        request = (
            SSH2_AGENTC_SIGN_REQUEST +
            encode_s(self.contents) +
            encode_s(challenge) +
            struct.pack('>L', 0)    # flags == 0
        )
        sock.sendall(encode_s(request))

        with should_exhaust(read_s(sock)) as msg:
            if msg.read(1) != SSH2_AGENT_SIGN_RESPONSE:
                raise ValueError('Expected SSH2_AGENT_SIGN_RESPONSE')
            signature = read_s(msg)

        with should_exhaust(signature) as msg:
            if read_s(msg) != b'ssh-rsa':
                raise ValueError('Expected ssh-rsa')
            return read_s(msg)

    @classmethod
    def make(cls, sock: Readable) -> 'Key':
        return cls(read_s(sock), read_s(sock))


def list_identities(sock: socket.socket) -> Dict[bytes, Key]:
    sock.sendall(encode_s(SSH2_AGENTC_REQUEST_IDENTITIES))

    with should_exhaust(read_s(sock)) as msg:
        if msg.read(1) != SSH2_AGENT_IDENTITIES_ANSWER:
            raise ValueError('expected SSH2_AGENT_IDENTITIES_ANSWER')

        keys = [Key.make(msg) for i in range(read_u32(msg))]
        return {key.comment: key for key in keys}


class Encrypted(NamedTuple):
    challenge: bytes
    salt: bytes
    payload: bytes

    def to_dct(self) -> Dict[str, str]:
        return {
            'challenge': base64.b64encode(self.challenge).decode(),
            'salt': base64.b64encode(self.salt).decode(),
            'payload': self.payload.decode(),
        }

    @classmethod
    def from_dct(cls, dct: Dict[str, str]) -> 'Encrypted':
        return cls(
            challenge=base64.b64decode(dct['challenge']),
            salt=base64.b64decode(dct['salt']),
            payload=dct['payload'].encode(),
        )


def get_key(keyid: bytes, challenge: bytes, salt: bytes) -> Fernet:
    """sign the challenge and use the signature blob as a symmetric key"""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0) as sock:
        sock.connect(os.environ['SSH_AUTH_SOCK'])

        key = list_identities(sock)[keyid]
        signature_blob = key.sign(sock, challenge)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return Fernet(base64.urlsafe_b64encode(kdf.derive(signature_blob)))


def encrypt(contents: str, keyid: bytes) -> Encrypted:
    data = contents.encode()
    challenge = os.urandom(64)  # same as sshcrypt
    salt = os.urandom(16)  # cryptography docs
    key = get_key(keyid, challenge, salt)
    return Encrypted(challenge=challenge, salt=salt, payload=key.encrypt(data))


def decrypt(contents: str, keyid: bytes) -> str:
    encrypted = Encrypted.from_dct(json.loads(contents))
    key = get_key(keyid, encrypted.challenge, encrypted.salt)
    return key.decrypt(encrypted.payload).decode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--filename', default='/dev/stdin')
    parser.add_argument('--key', default=os.path.expanduser('~/.ssh/id_rsa'))
    mutex = parser.add_mutually_exclusive_group(required=True)
    mutex.add_argument('--encrypt', action='store_true')
    mutex.add_argument('--decrypt', action='store_true')
    args = parser.parse_args()

    keyid = args.key.encode()
    with open(args.filename) as f:
        contents = f.read()

    if args.encrypt:
        encrypted = encrypt(contents, keyid)
        print(json.dumps(encrypted.to_dct(), indent=2))
    else:
        print(decrypt(contents, keyid), end='')
    return 0


if __name__ == '__main__':
    exit(main())
