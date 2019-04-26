import mow
import mock
import unittest


class TestMowInit(unittest.TestCase):
    def test_default_values(self):
        overflow = mow.Overflow(1, 2, mow.LITTLE_ENDIAN)
        self.assertEqual(overflow._register_dist, 1)
        self.assertEqual(overflow._register_count, 2)
        self.assertEqual(overflow._endianess, mow.LITTLE_ENDIAN)
        self.assertEqual(overflow._padding, 0)
        self.assertEqual(overflow._gadget_base, 0)
        self.assertEqual(overflow._overflow_string_contents, '')
        self.assertEqual(overflow._bad_bytes, None)

    def test_settings_values(self):
        overflow = mow.Overflow(1, 2, mow.LITTLE_ENDIAN, padding_after_ra=5,
                                gadgets_base=6, overflow_string_contents='a',
                                bad_bytes=[1])
        self.assertEqual(overflow._register_dist, 1)
        self.assertEqual(overflow._register_count, 2)
        self.assertEqual(overflow._endianess, mow.LITTLE_ENDIAN)
        self.assertEqual(overflow._padding, 5)
        self.assertEqual(overflow._gadget_base, 6)
        self.assertEqual(overflow._overflow_string_contents, 'a')
        self.assertEqual(overflow._bad_bytes, [b'\x01'])

    def test_register_count_low(self):
        with self.assertRaises(Exception):
            mow.Overflow(1, -1, mow.LITTLE_ENDIAN)

    def test_register_count_high(self):
        with self.assertRaises(Exception):
            mow.Overflow(1, 10, mow.LITTLE_ENDIAN)

    def test_bad_endian_value(self):
        with self.assertRaises(Exception):
            mow.Overflow(1, 1, 'big')

    def _test_registers(self, overflow, reg_set, not_set):
        for reg in reg_set:
            try:
                self.assertTrue(hasattr(overflow, reg))
            except:
                raise Exception('Overflow does not have %s defined' % reg)

        for reg in not_set:
            try:
                self.assertFalse(hasattr(overflow, reg))
            except:
                raise Exception('Overflow has %s defined incorrectly' % reg)

    def test_no_registers(self):
        overflow = mow.Overflow(1, 0, mow.LITTLE_ENDIAN)
        self._test_registers(overflow, [],
                             ['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
                              'fp'])

    def test_one_registers(self):
        overflow = mow.Overflow(1, 1, mow.LITTLE_ENDIAN)
        self._test_registers(overflow, ['s0'],
                             ['s1', 's2', 's3', 's4', 's5', 's6', 's7',
                              'fp'])

    def test_two_registers(self):
        overflow = mow.Overflow(1, 2, mow.LITTLE_ENDIAN)
        self._test_registers(overflow, ['s0', 's1'],
                             ['s2', 's3', 's4', 's5', 's6', 's7',
                              'fp'])

    def test_three_registers(self):
        overflow = mow.Overflow(1, 3, mow.LITTLE_ENDIAN)
        self._test_registers(overflow, ['s0', 's1', 's2'],
                             ['s3', 's4', 's5', 's6', 's7', 'fp'])

    def test_four_registers(self):
        overflow = mow.Overflow(1, 4, mow.LITTLE_ENDIAN)
        self._test_registers(overflow, ['s0', 's1', 's2', 's3'],
                             ['s4', 's5', 's6', 's7', 'fp'])

    def test_five_registers(self):
        overflow = mow.Overflow(1, 5, mow.LITTLE_ENDIAN)
        self._test_registers(overflow, ['s0', 's1', 's2', 's3', 's4'],
                             ['s5', 's6', 's7', 'fp'])

    def test_six_registers(self):
        overflow = mow.Overflow(1, 6, mow.LITTLE_ENDIAN)
        self._test_registers(overflow, ['s0', 's1', 's2', 's3', 's4', 's5'],
                             ['s6', 's7', 'fp'])

    def test_seven_registers(self):
        overflow = mow.Overflow(1, 7, mow.LITTLE_ENDIAN)
        self._test_registers(overflow,
                             ['s0', 's1', 's2', 's3', 's4', 's5', 's6'],
                             ['s7', 'fp'])

    def test_eight_registers(self):
        overflow = mow.Overflow(1, 8, mow.LITTLE_ENDIAN)
        self._test_registers(overflow,
                             ['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7'],
                             ['fp'])

    def test_nine_registers(self):
        overflow = mow.Overflow(1, 9, mow.LITTLE_ENDIAN)
        self._test_registers(overflow,
                             ['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
                              'fp'],
                             [])

    def test_register_values(self):
        overflow = mow.Overflow(1, 9, mow.LITTLE_ENDIAN)
        self.assertEqual(overflow.s0, b'AAAA')
        self.assertEqual(overflow.s1, b'BBBB')
        self.assertEqual(overflow.s2, b'CCCC')
        self.assertEqual(overflow.s3, b'DDDD')
        self.assertEqual(overflow.s4, b'EEEE')
        self.assertEqual(overflow.s5, b'FFFF')
        self.assertEqual(overflow.s6, b'GGGG')
        self.assertEqual(overflow.s7, b'HHHH')
        self.assertEqual(overflow.fp, b'IIII')


if __name__ == '__main__':
    unittest.main()
