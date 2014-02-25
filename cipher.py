#!/usr/bin/env python


class cipher(object):
    """
    Base class for ciphers. Performs identity cipher.

    >>> cipher().encode('ABCD')
    'ABCD'
    >>> cipher(alphabet='').encode('ABCD')
    Traceback (most recent call last):
      ...
    ValueError: substring not found
    """
    def __init__(self, **kwargs):
        self.alphabet = kwargs.pop('alphabet', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')

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


if __name__ == '__main__':
    import doctest
    doctest.testmod()
