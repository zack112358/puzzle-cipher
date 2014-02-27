#!/usr/bin/env python

"""
Module describing a bunch of simple ciphers for making puzzles. None of them
have any particular cryptographic merit as such, but they're 

>>> 'ABCD' | CaesarCipher()
'NOPQ'
>>> 'ABCD' | CaesarCipher() | CaesarCipher()
'ABCD'
"""

import random
import re
from fractions import gcd
from string import punctuation
from itertools import chain, islice

class Cipher(object):
    """
    Base class for ciphers. Performs identity cipher.

    >>> Cipher().encode('ABCD')
    'ABCD'
    >>> Cipher(alphabet='').encode('ABCD')
    Traceback (most recent call last):
      ...
    AlphabetError: 'A' not in alphabet
    >>> Cipher(seed=1).random.random() == Cipher(seed=1).random.random()
    True
    """
    def __init__(self, **kwargs):
        self.alphabet = kwargs.pop('alphabet', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        self.seed = kwargs.pop('seed', 0)
        self.random = kwargs.pop('random', random.Random())
        if self.seed is not None:
            self.random.seed(self.seed)
        super(Cipher, self).__init__(**kwargs)

    def reset(self):
        self.random.seed(self.seed)

    def ords(self, text):
        """ Translate text to indices into the alphabet """
        return map(self.ord, text)

    def ord(self, char):
        """ Translate character to index into the alphabet """
        if isinstance(char, str) and len(char) == 1:
            try:
                return self.alphabet.index(char)
            except ValueError:
                raise self.AlphabetError("%r not in alphabet" % char)
        else:
            return char  # Pass through if already an offset

    def chrs(self, offsets):
        """ Translate indices to text """
        return ''.join(map(self.chr, offsets))

    def chr(self, offset):
        """ Translate index to character """
        return self.alphabet[offset]

    def encode(self, plaintext):
        """ Translate plaintext to ciphertext """
        return self.chrs(self.encode_ords(plaintext))

    def encode_ords(self, plaintext):
        """ Translate plaintext to cipher indices """
        self.reset()
        return self._encode_ords(self.ords(plaintext))

    def _encode_ords(self, plainords):
        """ OVERRIDE ME: translate plain indices to cipher indices """
        return plainords

    def __or__(self, other):
        if not isinstance(Cipher, other):
            raise TypeError("Can only compose ciphers with other ciphers")
        return ComposedCipher(children=(self, other))

    def __ror__(self, other):
        return self.encode(other)

    class AlphabetError(Exception):
        pass


class SubstitutionCipher(Cipher):
    """ Substitution cipher base class """
    def __init__(self, **kwargs):
        super(SubstitutionCipher, self).__init__(**kwargs)

    def _encode_ords(self, plain_ords):
        return map(self._encode_ord, plain_ords)


class CaesarCipher(SubstitutionCipher):
    """
    Rot-by-N cipher.
    
    >>> CaesarCipher(rot_by=13).encode('ABCD')
    'NOPQ'
    >>> CaesarCipher(rot_by=26).encode('ABCD')
    'ABCD'
    """

    def __init__(self, **kwargs):
        self.rot_by = kwargs.pop('rot_by', 13)
        super(CaesarCipher, self).__init__(**kwargs)

    def _encode_ord(self, plain_ord):
        return (plain_ord + self.rot_by) % len(self.alphabet)


class MapSubstitutionCipher(SubstitutionCipher):
    """
    Arbitrary substitution cipher using a mapping of indices into the alphabet.
    Anything that can be subscripted by the plaintext index to get the
    ciphertext index can be used as the mapping.

    >>> MapSubstitutionCipher(mapping={0:2,1:3,3:1,2:0}).encode('ABCD')
    'CDAB'
    >>> MapSubstitutionCipher(mapping=[0,1,2,3]).encode('ABCD')
    'ABCD'
    >>> a = MapSubstitutionCipher().encode('ABCD')
    >>> MapSubstitutionCipher().encode('ABCD') == a
    True
    """
    def __init__(self, **kwargs):
        self.mapping = kwargs.pop('mapping', None)
        super(MapSubstitutionCipher, self).__init__(**kwargs)
        # random initialization only *after* call to super sets up our RNG
        if self.mapping is None:
            self.mapping = self.random_mapping()

    def _encode_ord(self, plain_ord):
        return self.mapping[plain_ord]

    def random_mapping(self):
        mapping = range(len(self.alphabet))
        self.random.shuffle(mapping)
        return mapping


class SkewedOneTimePadCipher(SubstitutionCipher):
    """
    One-time-pad cipher. Since we use Mersenne Twister, not cryptographically
    secure. However, still effective for puzzle-level analysis. In order that
    the cipher still be breakable, we need to have a very skewed distribution of
    random numbers.

    >>> SkewedOneTimePadCipher(skew=26).encode('A'*50)
    'BBAAAABAAACAABAACEBCABCBAAAACDACABAABABBAACAACAAAD'
    """

    def __init__(self, **kwargs):
        self.skew = kwargs.pop('skew', 1) * 1.0
        super(SkewedOneTimePadCipher, self).__init__(**kwargs)

    def _encode_ord(self, plain_ord):
        # Repeatable due to use of fixed random seed
        alpha_size = len(self.alphabet)
        pad_value = int(self.random.expovariate(self.skew / alpha_size))
        return (plain_ord + pad_value) % alpha_size


class ReprCipherMixin(Cipher):
    """
    Mixin makes a cipher's encoded output into representations of its "ordinal"
    values instead of just chr translation --- useful if encode_ords returns
    structures instead of numbers
    """
    def encode(self, plaintext):
        """ Translate plaintext to ciphertext """
        return ' '.join(map(repr, self.encode_ords(plaintext)))


class GCDCipher(SubstitutionCipher, ReprCipherMixin):
    """
    This one is a little more creative. Each ordinal is represented by a pair of
    numbers whose GCD is the ordinal plus one. As a consequence the output
    doesn't map back to the alphabet without additional massaging.

    >>> map(lambda pair:gcd(*pair), GCDCipher().encode_ords('ABCD'))
    [1, 2, 3, 4]
    """
    def _encode_ord(self, plain_ord):
        divisor = plain_ord + 1
        a = 2
        b = 2
        while gcd(a, b) > 1:
            a = self.random.randrange(1000 // divisor)
            b = self.random.randrange(1000 // divisor)
        return (a * divisor, b * divisor)


class SimpleFeedbackCipher(SubstitutionCipher):
    """
    For this one, we feed back our output characters into the input so that
    output_i = input_i + output_{i-1}

    >>> SimpleFeedbackCipher().encode('AAAABBBBCCCCDDDD')
    'NNNNOPQRTVXZCFIL'
    """

    def __init__(self, **kwargs):
        self.init_rot_by = kwargs.pop('init_rot_by', 13)
        super(SimpleFeedbackCipher, self).__init__(**kwargs)

    def _encode_ord(self, plain_ord):
        output = (plain_ord + self.feedback) % len(self.alphabet)
        self.feedback = output
        return output

    def reset(self):
        super(SimpleFeedbackCipher, self).reset()
        self.feedback = self.init_rot_by


class SquareFeedbackCipher(SimpleFeedbackCipher):
    """
    For this one, we feed back our output characters into the input so that
    output_i = input_i + output_{i-1}

    >>> SimpleFeedbackCipher().encode('AAAABBBBCCCCDDDD')
    'NNNNOPQRTVXZCFIL'
    """

    def _encode_ord(self, plain_ord):
        output = (plain_ord + self.feedback ** 2) % len(self.alphabet)
        self.feedback = output
        return output


class IndexedSubstitutionCipher(Cipher):
    """
    Substitution cipher base class that also passes offset to _encode_ord

    >>> 'ABCD' | IndexedSubstitutionCipher()
    'ABCD'
    """
    def __init__(self, **kwargs):
        super(IndexedSubstitutionCipher, self).__init__(**kwargs)

    def _encode_ords(self, plain_ords):
        i = 0
        for plain_ord in plain_ords:
            yield self._encode_ord(plain_ord, i)
            i += 1

    def _encode_ord(self, plain_ord, i):
        return plain_ord


class RotatingCipher(IndexedSubstitutionCipher):
    """
    Caesar cipher where key rotates by fixed amount each letter

    >>> RotatingCipher().encode('AAAA')
    'NOPQ'
    >>> RotatingCipher().encode('AZYX')
    'NNNN'
    """
    def __init__(self, **kwargs):
        self.init_rot_by = kwargs.pop('init_rot_by', 13)
        self.increment = kwargs.pop('increment', 1)
        super(RotatingCipher, self).__init__(**kwargs)

    def _encode_ord(self, plain, i):
        alpha_size = len(self.alphabet)
        return (plain + self.init_rot_by + self.increment * i) % alpha_size


class ComposedCipher(Cipher):
    """
    Composition of two ciphers.

    >>> rot13 = CaesarCipher(rot_by=13)
    >>> inverserot13 = CaesarCipher(rot_by=-13)
    >>> ComposedCipher(children=(rot13, inverserot13)).encode('ABCD')
    'ABCD'
    >>> 'ABCD' | rot13 | inverserot13
    'ABCD'
    """
    def __init__(self, **kwargs):
        self.children = kwargs.pop('children')
        super(ComposedCipher, self).__init__(**kwargs)

    def _encode_ords(self, ords):
        for cipher in self.children:
            ords = cipher.encode_ords(ords)
        return ords


class Smasher(Cipher):
    """
    Not really a cipher; this simple filter smashes non-essential characters
    out of the input.

    >>> 'ALSw#SI#UR as.,f' | Smasher()
    'ALSWSIURASF'
    """
    def encode_ords(self, plaintext):
        smashed = [c for c in plaintext
                   if not c.isspace() and c not in punctuation]
        smashed = [c.upper() if c.upper() in self.alphabet else 'X'
                   for c in smashed]
        return map(self.ord, smashed)


class ColumnarCipher(Cipher):
    """
    Simple cipher based on matrix transposition. Input

    1 2 3 4 5 6 7 8 9
    
    is written row-major as

    1 2 3 
    4 5 6
    7 8 9

    and output is read column-major to get

    1 4 7 2 5 8 3 6 9

    >>> 'ABCDEFGHI' | ColumnarCipher(width=3)
    'ADGBEHCFI'
    >>> 'ABCDEFGHI' | ColumnarCipher(width=3, column_order=[2, 0, 1])
    'CFIADGBEH'
    """
    def __init__(self, **kwargs):
        self.width = kwargs.pop('width', 3)
        self.column_order = kwargs.pop('column_order', range(self.width))
        super(ColumnarCipher, self).__init__(**kwargs)

    def _encode_ords(self, plaintext):
        # Save our input in case it's an iterator
        text = list(plaintext)
        while len(text) % self.width:
            text.append('X')
        height = len(text) // self.width
        for i in range(len(text)):
            yield text[i * self.width % len(text) + 
                       self.column_order[i // height]]


class OneTimePadCipher(IndexedSubstitutionCipher):
    """
    Uses a one-time-pad you specify. Another way to look at it is that it
    merges two input streams of text.

    >>> 'ABCD' | OneTimePadCipher(pad='AAAA')
    'ABCD'
    >>> 'ABCD' | OneTimePadCipher(pad=[0, -1, -2, -3])
    'AAAA'
    """
    def __init__(self, **kwargs):
        self.pad = kwargs.pop('pad')
        super(OneTimePadCipher, self).__init__(**kwargs)
        # Only use ord after the alphabet has been set by super init
        self.pad = map(self.ord, self.pad)

    def _encode_ord(self, plain_ord, i):
        return (self.pad[i] + plain_ord) % len(self.alphabet)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
