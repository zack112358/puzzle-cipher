#!/usr/bin/env python

import random

class Cipher(object):
    """
    Base class for ciphers. Performs identity cipher.

    >>> Cipher().encode('ABCD')
    'ABCD'
    >>> Cipher(alphabet='').encode('ABCD')
    Traceback (most recent call last):
      ...
    ValueError: substring not found
    >>> Cipher(seed=1).random.random() == Cipher(seed=1).random.random()
    True
    """
    def __init__(self, **kwargs):
        self.alphabet = kwargs.pop('alphabet', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        self.seed = kwargs.pop('seed', 0)
        self.random = kwargs.pop('random', random.Random())
        self.random.seed(self.seed)
        super(Cipher, self).__init__(**kwargs)

    def reset_rand(self):
        self.random.seed(self.seed)

    def ords(self, text):
        """ Translate text to indices into the alphabet """
        return map(self.ord, text)

    def ord(self, char):
        """ Translate character to index into the alphabet """
        if isinstance(char, str):
            return self.alphabet.index(char)
        elif isinstance(char, int):
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
        self.reset_rand()
        return self._encode_ords(self.ords(plaintext))

    def _encode_ords(self, plainords):
        """ OVERRIDE ME: translate plain indices to cipher indices """
        return plainords



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


if __name__ == '__main__':
    import doctest
    doctest.testmod()
