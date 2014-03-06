import unittest

from camcrypt import BLOCK_SIZE, CamCrypt, zero_pad

ZERO_BUF = "\x00" * 16

class CamCryptTests(unittest.TestCase):

    def test_zero_pad(self):
        self.assertEqual(ZERO_BUF, zero_pad("", 16))
        self.assertEqual('a' + "\x00" * 15, zero_pad("a", 16))
        self.assertEqual('aa' + "\x00" * 14, zero_pad("aa", 16))
        self.assertEqual('aaa' + "\x00" * 13, zero_pad("aaa", 16))
        self.assertEqual('aaaa' + "\x00" * 12, zero_pad("aaaa", 16))
        self.assertEqual('a' * 5 + "\x00" * 11, zero_pad("a" * 5, 16))
        self.assertEqual('a' * 6 + "\x00" * 10, zero_pad("a" * 6, 16))
        self.assertEqual('a' * 7 + "\x00" * 9, zero_pad("a" * 7, 16))
        self.assertEqual('a' * 8 + "\x00" * 8, zero_pad("a" * 8, 16))
        self.assertEqual('a' * 9 + "\x00" * 7, zero_pad("a" * 9, 16))
        self.assertEqual('a' * 10 + "\x00" * 6, zero_pad("a" * 10, 16))
        self.assertEqual('a' * 11 + "\x00" * 5, zero_pad("a" * 11, 16))
        self.assertEqual('a' * 12 + "\x00" * 4, zero_pad("a" * 12, 16))
        self.assertEqual('a' * 13 + "\x00" * 3, zero_pad("a" * 13, 16))
        self.assertEqual('a' * 14 + "\x00" * 2, zero_pad("a" * 14, 16))
        self.assertEqual('a' * 15 + "\x00" * 1, zero_pad("a" * 15, 16))
        self.assertEqual('a' * 16, zero_pad("a" * 16, 16))

    def test_encrypt(self):
        c = CamCrypt()
        c.keygen(128, "\x80" + "\x00" * 15)
        expected = "6c227f749319a3aa7da235a9bba05a2c"
        self.assertEqual(expected, c.encrypt(ZERO_BUF).encode("hex"))

    def test_encrypt_block(self):
        c = CamCrypt()
        c.keygen(128, "\x80" + "\x00" * 15)
        expected = "6c227f749319a3aa7da235a9bba05a2c"
        self.assertEqual(expected, c.encrypt_block(ZERO_BUF).encode("hex"))

    def test_decrypt(self):
        c = CamCrypt()
        c.keygen(128, "\x80" + "\x00" * 15)
        encrypted = "6c227f749319a3aa7da235a9bba05a2c".decode("hex")
        self.assertEqual(ZERO_BUF, c.decrypt(encrypted))

    def test_decrypt_block(self):
        c = CamCrypt()
        c.keygen(128, "\x80" + "\x00" * 15)
        encrypted = "6c227f749319a3aa7da235a9bba05a2c".decode("hex")
        self.assertEqual(ZERO_BUF, c.decrypt_block(encrypted))

    def test_errors(self):
        c = CamCrypt()
        c.keygen(128, "\x80" + "\x00" * 15)
        self.assertRaises(ValueError, c.encrypt_block, 'a')

if __name__ == '__main__':
    unittest.main()
