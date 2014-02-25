#!/usr/bin/env python


class Cipher(object):
    """
    Base class for ciphers. Performs identity cipher.

    >>> Cipher().encode('ABCD')
    'ABCD'
    >>> Cipher(alphabet='').encode('ABCD')
    Traceback (most recent call last):
      ...
    ValueError: substring not found
    """
    def __init__(self, **kwargs):
        self.alphabet = kwargs.pop('alphabet', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        super(Cipher, self).__init__(**kwargs)

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
        return self._encode_ords(self.ords(plaintext))

    def _encode_ords(self, plainords):
        """ OVERRIDE ME: translate plain indices to cipher indices """
        return plainords


class SubstitutionCipher(Cipher):
    """ Substitution cipher base class """
    def _encode_ords(self, plain_ords):
        return map(self._encode_ord, plain_ords)

class Rot(SubstitutionCipher):
    """
    Rot-by-N cipher.
    
    >>> Rot(rot_by=13).encode('ABCD')
    'NOPQ'
    >>> Rot(rot_by=26).encode('ABCD')
    'ABCD'
    """

    def __init__(self, **kwargs):
        self.rot_by = kwargs.pop('rot_by', 13)
        super(Rot, self).__init__(**kwargs)

    def _encode_ord(self, plain_ord):
        return (plain_ord + self.rot_by) % len(self.alphabet)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
