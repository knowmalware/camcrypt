= OVERVIEW =

CamCrypt is a simple Python wrapper around one of the open source
implementations of the Camellia encryption library.  It makes use of
the Python ctypes module to reference the functions available in the
C library.


= CAVEATS =

The current version is only setup for Unix/Linux environments, but
should be easy to modify for MS-Windows for those familiar with the
Python ctypes modules.


= USAGE =

First, compile the C code into a shared library:
  $ make

Next, copy the shared library and Python file to your project:
  $ cp camellia.so camcrypt.py DEST/

Import the module into your script:
  import camcrypt
Create a CamCrypt object, providing it the shared library path:
  mycrypt = camcrypt.CamCrypt(LIBRARY_PATH)
Initialize the keytable with the number of key bits and a key/passphrase:
  mycrypt.keygen(128, "password")
Encrypt in blocks of 16 bytes:
  ciphertext = mycrypt.encrypt(plaintext)
Or decrypt in blocks of 16 bytes:
  plaintext = mycrypt.decrypt(ciphertext)
  

= BASIC INFORMATION =

Updates and contact information may be found on the project's website:
  https://github.com/knowmalware/camcrypt

Current version is 1.1.0, corresponding with the C implementation
included with this module.  The C code was copied from:
  http://info.isl.ntt.co.jp/crypt/eng/camellia/dl/camellia-GPL-1.1.0.tar.gz
UPDATE 2013-07-02: version is 1.1.1, for patch to compile properly on OS X

= ACKNOWLEDGEMENTS =

2013-07-02: Thanks to Andy Schworer (@schwo) for the patch to allow the
camellia C implementation to compile properly on OS X. 
