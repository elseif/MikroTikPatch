#!/usr/bin/env python
#
# Copyright (c) 2012 Dave Pifke.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#

"""SHA256 (FIPS 180-3) implementation for experimentation."""

import binascii
import codecs
import collections
import struct
import sys

if sys.version > '3':
    long = int


class SHA256(object):
    """
    SHA256 (FIPS 180-3) implementation for experimentation.

    This is an implementation of the hash function designed not for
    efficiency, but for clarity and ability to experiment.  The details
    of the algorithm are abstracted out with subclassing in mind.

    """

    # Container for the state registers between rounds:
    State = collections.namedtuple('State', 'a b c d e f g h')

    # From FIPS 180-3 section 5.3.3 (page 15):
    INITIAL_STATE = State(
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    )

    # From FIPS 180-3 section 4.2.2 (page 11):
    K = (
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    )

    # Abstract bitwise operations, which can be overridden to provide tracing
    # or alternate implementations:
    @staticmethod
    def _sum_mod32(*args):
        return sum(args) & 0xffffffff
    @classmethod
    def _xor(cls, *args):
        if len(args) == 2:
            return args[0] ^ args[1]
        else:
            return args[0] ^ cls._xor(*args[1:])
    _and = staticmethod(lambda x, y: x & y)
    _invert = staticmethod(lambda x: ~x)

    # Operations defined by FIPS 180-3 section 3.2 (page 8):
    _rrot = staticmethod(lambda x, n: ((x & 0xffffffff) >> n) | (x << (32 - n)) & 0xffffffff)
    _shr = staticmethod(lambda x, n: (x & 0xffffffff) >> n)

    # Operations defined by FIPS 180-3 section 4.1.2 (page 10):
    _ch = classmethod(lambda cls, x, y, z: cls._xor(cls._and(x, y), cls._and(cls._invert(x), z)))
    _maj = classmethod(lambda cls, x, y, z: cls._xor(cls._and(x, y), cls._and(x, z), cls._and(y, z)))
    _S0 = classmethod(lambda cls, x: cls._xor(cls._rrot(x, 2), cls._rrot(x, 13), cls._rrot(x, 22)))
    _S1 = classmethod(lambda cls, x: cls._xor(cls._rrot(x, 6), cls._rrot(x, 11), cls._rrot(x, 25)))
    _s0 = classmethod(lambda cls, x: cls._xor(cls._rrot(x, 7), cls._rrot(x, 18), cls._shr(x, 3)))
    _s1 = classmethod(lambda cls, x: cls._xor(cls._rrot(x, 17), cls._rrot(x, 19), cls._shr(x, 10)))

    # Operations defined by FIPS 180-3 section 6.2.2 (page 22):
    _T1 = classmethod(lambda cls, prev, w, k: cls._sum_mod32(cls._S1(prev.e), cls._ch(prev.e, prev.f, prev.g), prev.h, w, k))
    _T2 = classmethod(lambda cls, prev: cls._sum_mod32(cls._S0(prev.a), cls._maj(prev.a, prev.b, prev.c)))

    @classmethod
    def _round(cls, number, w, prev=INITIAL_STATE):
        """
        Performs one round of SHA256 message transformation, returning the new
        message state.  See FIPS 180-3 section 6.2.2 step 3 (pages 21-22).

        :param number:
            The round number.

        :param w:
            The expanded word of the input for this round.

        :param prev:
            Named tuple containing the working state from the previous round.

        """

        t1 = cls._T1(prev, w, cls.K[number % 64])
        return cls.State(
            a=cls._sum_mod32(t1, cls._T2(prev)),
            b=prev.a,
            c=prev.b,
            d=prev.c,
            e=cls._sum_mod32(prev.d, t1),
            f=prev.e,
            g=prev.f,
            h=prev.g
        )

    @classmethod
    def _finalize(cls, state, initial_state=INITIAL_STATE):
        """
        Returns the intermediate state after the final round for a given block
        is complete.  See FIPS 180-3 section 6.2.2 step 4 (page 22).

        :param state:
            The digest state after the final round.

        :param initial_state:
            The digest state from before the first round.

        """

        return cls.State(
            a=cls._sum_mod32(state.a, initial_state.a),
            b=cls._sum_mod32(state.b, initial_state.b),
            c=cls._sum_mod32(state.c, initial_state.c),
            d=cls._sum_mod32(state.d, initial_state.d),
            e=cls._sum_mod32(state.e, initial_state.e),
            f=cls._sum_mod32(state.f, initial_state.f),
            g=cls._sum_mod32(state.g, initial_state.g),
            h=cls._sum_mod32(state.h, initial_state.h)
        )

    @classmethod
    def _expand_message(cls, message):
        """
        Returns a list of 64 32-bit words based upon 16 32-bit words from the
        message block being hashed.  See FIPS 180-3 section 6.2.2 step 1
        (page 21).

        :param message:
            Array of 16 32-bit values (512 bits total).

        """

        assert len(message) == 16, '_expand_message() got %d words, expected 16' % len(message)

        w = list(message)
        for i in range(16, 64):
            w.append(cls._sum_mod32(w[i - 16], cls._s0(w[i - 15]), w[i - 7], cls._s1(w[i - 2])))

        return w

    @classmethod
    def _process_block(cls, message, state=INITIAL_STATE, round_offset=0):
        """
        Processes a block of message data, returning the new digest state
        (the intermediate hash value).  See FIPS 180-3 section 6.2.2 (pages
        21 and 22).

        :param message:
            Byte string of length 64 containing the block data to hash.

        :param state:
            The digest state from the previous block.

        :param round_offset:
            The _round() method can be overridden to report intermediate hash
            values, in which case it's useful to know how many rounds came
            before.  This argument allows the caller to specify as much.

        """

        assert len(message) == 64, '_process_block() got %d bytes, expected 64' % len(message)
        assert not round_offset % 64, 'round_offset should be a multiple of 64'

        w = cls._expand_message(struct.unpack('>LLLLLLLLLLLLLLLL', message))

        midstate = state
        for i in range(64):
            midstate = cls._round(round_offset + i, w[i], midstate)

        return cls._finalize(midstate, state)

    @classmethod
    def _pad_message(cls, message, length):
        """
        Returns a list containing the final 1 or 2 message blocks, which
        include the message padding per FIPS 180-3 section 5.1.1 (page 13).

        :param message:
            Byte string containing the final block data to hash.  Should be
            less than a full block's worth (63 bytes or less).

        :param length:
            Length of the message, in bits.

        """

        assert len(message) < 64, 'Input to _pad_message() must be less than 512 bits'

        if len(message) <= 55:
            # Append trailing 1 bit, then padding, then length
            return [b''.join((
                message,
                b'\x80',
                b'\x00' * (55 - len(message)),
                struct.pack('>LL', length >> 32, length & 0xffffffff),
            ))]

        else:
            # Not enough room to append length, return two blocks:
            return [
                # First is trailing 1 bit, then padding
                b''.join((
                    message,
                    b'\x80',
                    b'\x00' * (63 - len(message)),
                )),
                # Next is more padding, then length
                b''.join((
                    b'\x00' * 56,
                    struct.pack('>LL', length >> 32, length & 0xffffffff),
                )),
            ]

    def __init__(self, message=b'', round_offset=0):
        """
        Constructor.

        :param message:
            Initial data to pass to update().

        :param round_offset:
            The _round() method can be overridden to report intermediate hash
            values, in which case it's useful to know how many rounds came
            before.  For applications that perform double-hashing, you can
            specify the number of rounds from the previous hash instance
            using this parameter.

        """

        self.state = self.INITIAL_STATE
        self.length = long(0)
        self.buffer = b''
        self.round_offset = round_offset

        self.update(message)

    def update(self, message):
        """
        Updates the hash with the contents of *message*.

        Hashing uses 512-bit blocks, so the message is buffered until there's
        enough data to process a complete block.  When digest() is called,
        any remaining data in the buffer will be padded and digested.

        :param message:
            A byte string to digest.

        """

        message = bytes(message)
        self.length += len(message) * 8
        self.buffer = b''.join((self.buffer, message))

        while len(self.buffer) >= 64:
            self.state = self._process_block(self.buffer[:64], self.state, self.round_offset)
            self.buffer = self.buffer[64:]
            self.round_offset += 64

    def digest(self):
        """
        Returns the SHA256 digest of the message.

        The hash is based on all data passed thus far via the constructor and
        update().  Any buffered data will be processed (along with the
        terminating length), however the internal state is not modified.  This
        means that update() can safely be used again after digest().

        """

        final_state = self.state
        for block in self._pad_message(self.buffer, self.length):
            final_state = self._process_block(block, final_state, self.round_offset)

        return struct.pack('>LLLLLLLL', *final_state)

    def hexdigest(self):
        """Like digest(), but returns a hexadecimal string."""

        return binascii.hexlify(self.digest())