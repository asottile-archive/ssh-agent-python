import argparse
import codecs
import contextlib
import hashlib
import io
import os
import re
import socket
import struct
from typing import Callable
from typing import Dict
from typing import Generator
from typing import NamedTuple
from typing import Union

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


def read_bigint(sock: Readable) -> int:
    # https://github.com/python/typeshed/issues/300
    return int(codecs.encode(read_s(sock), 'hex'), 16)  # type: ignore


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
    comment: bytes
    contents: bytes
    public_exponent: int
    modulus: int

    def sign(self, sock: socket.socket, to_sign: bytes) -> int:
        request = (
            SSH2_AGENTC_SIGN_REQUEST +
            encode_s(self.contents) +
            encode_s(to_sign) +
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
            return read_bigint(msg)

    @classmethod
    def make(cls, sock: Readable) -> 'Key':
        contents = read_s(sock)
        comment = read_s(sock)

        with should_exhaust(contents) as msg:
            if read_s(msg) != b'ssh-rsa':
                raise ValueError('Expected ssh-rsa')
            public_exponent = read_bigint(msg)
            modulus = read_bigint(msg)

        return cls(comment, contents, public_exponent, modulus)


def list_identities(sock: socket.socket) -> Dict[bytes, Key]:
    sock.sendall(encode_s(SSH2_AGENTC_REQUEST_IDENTITIES))

    with should_exhaust(read_s(sock)) as msg:
        if msg.read(1) != SSH2_AGENT_IDENTITIES_ANSWER:
            raise ValueError('expected SSH2_AGENT_IDENTITIES_ANSWER')

        keys = [Key.make(msg) for i in range(read_u32(msg))]
        return {key.comment: key for key in keys}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--key', default=os.path.expanduser('~/.ssh/id_rsa'))
    parser.add_argument('--msg', default='hello world')
    args = parser.parse_args()

    key_comment = args.key.encode()
    to_sign = args.msg.encode()

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0) as sock:
        sock.connect(os.environ['SSH_AUTH_SOCK'])

        key = list_identities(sock)[key_comment]
        signature = key.sign(sock, to_sign)

    # Verify the signature.
    decoded_value = pow(signature, key.public_exponent, key.modulus)
    decoded_hex = f'{decoded_value:x}'
    if len(decoded_hex) % 2:
        decoded_hex = '0' + decoded_hex

    # https://github.com/python/typeshed/issues/300
    decoded_str: bytes = codecs.decode(decoded_hex, 'hex')  # type: ignore
    if not re.match(b'\x01\xff+$', decoded_str[:-36]):
        raise ValueError('bad padding found')

    expected_sha1_hex = decoded_hex[-40:]
    msg_sha1_hex = hashlib.sha1(to_sign).hexdigest()
    if expected_sha1_hex != msg_sha1_hex:
        raise ValueError('sha1 mismatch')
    else:
        print('matched!')

    return 0


if __name__ == '__main__':
    exit(main())
