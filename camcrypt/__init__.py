"""
CamCrypt provides a wrapper for a reference C implementation of
the Camellia cryptographic cipher.
"""

import ctypes
from os.path import dirname, join

__all__ = ['CamCrypt', 'version', 'BLOCK_SIZE', 'TABLE_BYTE_LEN']

_VERSION = "1.2.0"

def version():
  """ Return the library version string.
  """
  return _VERSION


DEFAULT_PATH = join(dirname(__file__), 'camellia.so')

BLOCK_SIZE = 16
TABLE_BYTE_LEN = 272


class CamCrypt(object):

  def __init__(self, libraryPath=DEFAULT_PATH):
    """ To instantiate an instance of this class, provide the full
    path to the camellia shared library (camellia.so) that it
    will reference.
    Raises an exception if the libraryPath is not specified or
    there is a problem loading the library. 
    """
    self._loadlib(libraryPath)
  
  def _loadlib(self, libraryPath):
    self._SHARED_LIBRARY = libraryPath
    if self._SHARED_LIBRARY == None:
      raise Exception("no libraryPath specified")
    cam = ctypes.CDLL(self._SHARED_LIBRARY)
    self.ekeygen = getattr(cam, "Camellia_Ekeygen")
    self.encblock = getattr(cam, "Camellia_EncryptBlock")
    self.decblock = getattr(cam, "Camellia_DecryptBlock")

  def keygen(self, keyBitLength, rawKey):
    """ This must be called on the object before any encryption or
    decryption can take place.  Provide it the key bit length,
    which must be 128, 192, or 256, and the key, which may be a
    sequence of bytes or a simple string.
    Does not return any value.
    Raises an exception if the arguments are not sane.
    """
    if keyBitLength != 128 and keyBitLength != 192 and keyBitLength != 256:
      raise Exception("keyBitLength must be 128, 192, or 256")
    self.bitlen = keyBitLength
    if len(rawKey) <= 0 or len(rawKey) > self.bitlen/8:
      raise Exception("rawKey must be less than or equal to keyBitLength/8 (%d) characters long" % (self.bitlen/8))
    keytable = ctypes.create_string_buffer(TABLE_BYTE_LEN)
    self.ekeygen(self.bitlen, rawKey, keytable)
    self.keytable = keytable

  def encrypt_block(self, plainText):
    """Encrypt a 16-byte block of data.

    NOTE: This function was formerly called `encrypt`, but was changed when
    support for encrypting arbitrary-length strings was added.

    Args:
        plainText (str): 16-byte data.

    Returns:
        16-byte str.

    Raises:
        ValueError if `plainText` is not BLOCK_SIZE (i.e. 16) bytes.
    """
    if len(plainText) != BLOCK_SIZE:
      raise ValueError("plainText must be %d bytes long (received %d bytes)" %
                       (BLOCK_SIZE, len(plainText)))
    cipher = ctypes.create_string_buffer(BLOCK_SIZE)
    self.encblock(self.bitlen, plainText, self.keytable, cipher)
    return cipher.raw

  def decrypt_block(self, cipherText):
    """Decrypt a 16-byte block of data.

    NOTE: This function was formerly called `decrypt`, but was changed when
    support for decrypting arbitrary-length strings was added.

    Args:
        cipherText (str): 16-byte data.

    Returns:
        16-byte str.

    Raises:
        ValueError if `cipherText` is not BLOCK_SIZE (i.e. 16) bytes.
    """
    if len(cipherText) != BLOCK_SIZE:
      raise ValueError("cipherText must be %d bytes long (received %d bytes)" %
                       (BLOCK_SIZE, len(cipherText)))
    plain = ctypes.create_string_buffer(BLOCK_SIZE)
    self.decblock(self.bitlen, cipherText, self.keytable, plain)
    return plain.raw
