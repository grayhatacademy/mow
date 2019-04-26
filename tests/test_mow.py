import mow
import mock
import unittest


class TestMowInit(unittest.TestCase):
    def test_default_values(self):
        overflow = mow.Overflow(1, 2, mow.LITTLE_ENDIAN)
        self.assertEqual(overflow._register_dist, 1)
        self.assertEqual(overflow._register_count, 2)
        self.assertEqual(overflow._endianess, mow.LITTLE_ENDIAN)
        self.assertEqual(overflow._padding_after_ra, 0)
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
        self.assertEqual(overflow._padding_after_ra, 5)
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


class TestPackRegisters(unittest.TestCase):
    def setUp(self):
        self.overflow = mow.Overflow(1, 0, mow.LITTLE_ENDIAN)

    def test_invalid_input(self):
        with self.assertRaises(Exception):
            self.overflow._pack_register('abcd')

    def test_bytes_type_has_bad_bytes(self):
        self.overflow._has_bad_bytes = mock.Mock()
        self.overflow._has_bad_bytes.return_value = True

        with self.assertRaises(Exception):
            self.overflow._pack_register(b'AAAA')
        self.overflow._has_bad_bytes.assert_called_once_with(b'AAAA')

    def test_bytes_type(self):
        self.overflow._has_bad_bytes = mock.Mock()
        self.overflow._has_bad_bytes.return_value = False

        result = self.overflow._pack_register(b'AAAA')
        self.assertEqual(result, b'AAAA')
        self.overflow._has_bad_bytes.assert_called_once_with(b'AAAA')

    def test_int_type_has_bad_bytes(self):
        self.overflow._has_bad_bytes = mock.Mock()
        self.overflow._has_bad_bytes.return_value = True

        with self.assertRaises(Exception):
            self.overflow._pack_register(0xDEADBEEF)
        self.overflow._has_bad_bytes.assert_called_once_with(
            b'\xEF\xBE\xAD\xDE')

    def test_int_type(self):
        self.overflow._has_bad_bytes = mock.Mock()
        self.overflow._has_bad_bytes.return_value = False

        result = self.overflow._pack_register(0xDEADBEEF)
        self.assertEqual(result, b'\xEF\xBE\xAD\xDE')
        self.overflow._has_bad_bytes.assert_called_once_with(
            b'\xEF\xBE\xAD\xDE')


class TestIsSafeWrite(unittest.TestCase):
    def setUp(self):
        self.overflow = mow.Overflow(1, 0, mow.LITTLE_ENDIAN)

    def test_bad_location(self):
        with self.assertRaises(Exception):
            self.overflow._is_safe_write(-1, 5)

    def test_bad_length(self):
        with self.assertRaises(Exception):
            self.overflow._is_safe_write(5, -1)

    def test_write_past_current_stack(self):
        self.overflow._stack_write = b''
        self.assertTrue(self.overflow._is_safe_write(30, 30))

    def test_unsafe_write(self):
        self.overflow._stack_write = b'XXXXAAAA'
        self.assertFalse(self.overflow._is_safe_write(4, 4))

    def test_safe_write(self):
        self.overflow._stack_write = b'XXXXAAAA'
        self.assertTrue(self.overflow._is_safe_write(0, 4))

    def test_end_of_stack(self):
        self.overflow._stack_write = b'XXXXAAXX'
        self.assertTrue(self.overflow._is_safe_write(6, 4))


class TestAddToStack(unittest.TestCase):
    def setUp(self):
        self.overflow = mow.Overflow(1, 0, mow.LITTLE_ENDIAN)

    def test_missing_param(self):
        with self.assertRaises(Exception):
            self.overflow.add_to_stack(10)

    def test_multiple_commands(self):
        with self.assertRaises(Exception):
            self.overflow.add_to_stack(10, 0x41414141, 'ls -la')

    def test_bad_type_address(self):
        with self.assertRaises(Exception):
            self.overflow.add_to_stack(10, address='ls -la')

    def test_address_not_four_bytes(self):
        self.overflow._stack_write = b''
        self.overflow.add_to_stack(5, address=0x4141)
        self.assertEqual(self.overflow._stack_write, b'XXXXXAA\x00\x00')

    def test_address_no_stack(self):
        self.overflow._stack_write = b''
        self.overflow.add_to_stack(5, address=0x41414141)
        self.assertEqual(self.overflow._stack_write, b'XXXXXAAAA')

    def test_address_with_stack(self):
        self.overflow._stack_write = b'XXXXXXXX'
        self.overflow.add_to_stack(0, address=0x41414141)
        self.assertEqual(self.overflow._stack_write, b'AAAAXXXX')

    def test_address_unsafe_write(self):
        self.overflow._stack_write = b'XFXXXXXX'
        with self.assertRaises(Exception):
            self.overflow.add_to_stack(0, address=0x41414141)

    def test_address_unsafe_write_force_overwrite(self):
        self.overflow._stack_write = b'XFXXXXXX'
        self.overflow.add_to_stack(0, address=0x41414141, force_overwrite=True)
        self.assertEqual(self.overflow._stack_write, b'AAAAXXXX')

    def test_address_half_stack(self):
        self.overflow._stack_write = b'XX'
        self.overflow.add_to_stack(0, address=0x41414141)
        self.assertEqual(self.overflow._stack_write, b'AAAA')

    def test_bad_type_command(self):
        with self.assertRaises(Exception):
            self.overflow.add_to_stack(10, command=0x41414141)

    def test_command_no_stack(self):
        self.overflow._stack_write = b''
        self.overflow.add_to_stack(5, command='ls -la')
        self.assertEqual(self.overflow._stack_write, b'XXXXXls -la')

    def test_command_with_stack(self):
        self.overflow._stack_write = b'XXXXXXXXXX'
        self.overflow.add_to_stack(0, command='ls -la')
        self.assertEqual(self.overflow._stack_write, b'ls -laXXXX')

    def test_command_unsafe_write(self):
        self.overflow._stack_write = b'AAAXXXXXXX'
        with self.assertRaises(Exception):
            self.overflow.add_to_stack(0, command='ls -la')

    def test_command_unsafe_write_force_overwrite(self):
        self.overflow._stack_write = b'AAAXXXXXXX'
        self.overflow.add_to_stack(0, command='ls -la', force_overwrite=True)
        self.assertEqual(self.overflow._stack_write, b'ls -laXXXX')

    def test_command_half_stack(self):
        self.overflow._stack_write = b'XXXX'
        self.overflow.add_to_stack(0, command='ls -la')
        self.assertEqual(self.overflow._stack_write, b'ls -la')


class TestHasBadBytes(unittest.TestCase):
    def setUp(self):
        self.overflow = mow.Overflow(1, 0, mow.LITTLE_ENDIAN,
                                     bad_bytes=[1, 2, 3])

    def test_no_bad_bytes_defined(self):
        self.overflow._bad_bytes = None
        self.assertFalse(self.overflow._has_bad_bytes(b'\x01AAA'))

    def test_has_bad_bytes(self):
        self.assertTrue(self.overflow._has_bad_bytes(b'\x01AAA'))

    def test_no_bad_bytes(self):
        self.assertFalse(self.overflow._has_bad_bytes(b'AAAA'))


class TestGenerate(unittest.TestCase):

    def test_small_overflow(self):
        self.overflow = mow.Overflow(0, 0, mow.BIG_ENDIAN)
        of = self.overflow.generate()
        self.assertEqual(of, b'JJJJ')

    def test_large_overflow(self):
        self.overflow = mow.Overflow(20, 9, mow.BIG_ENDIAN)
        self.overflow.ra = 0x41414141
        of = self.overflow.generate()
        self.assertEqual(of,
                         b'XXXXXXXXXXXXXXXXXXXXAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIAAAA')

    def test_padding_after_ra(self):
        self.overflow = mow.Overflow(5, 0, mow.BIG_ENDIAN, padding_after_ra=4)
        of = self.overflow.generate()
        self.assertEqual(of, b'XXXXXJJJJXXXX')

    def test_gadget_base(self):
        self.overflow = mow.Overflow(5, 0, mow.BIG_ENDIAN,
                                     gadgets_base=0x11111111)
        self.overflow.ra = 0x11111111
        of = self.overflow.generate()
        self.assertEqual(of, b'XXXXX\x22\x22\x22\x22')

    def test_overflow_string(self):
        self.overflow = mow.Overflow(8, 0, mow.BIG_ENDIAN,
                                     overflow_string_contents='abcd')
        of = self.overflow.generate()
        self.assertEqual(of, b'XXXXJJJJ')

    def test_bad_bytes(self):
        self.overflow = mow.Overflow(8, 1, mow.BIG_ENDIAN, bad_bytes=[0x41])
        self.s0 = 0x42424241
        with self.assertRaises(Exception):
            self.overflow.generate()

    def test_bad_bytes_in_stack(self):
        self.overflow = mow.Overflow(8, 0, mow.BIG_ENDIAN, bad_bytes=[0x41])
        self.overflow.add_to_stack(10, command='FDSA')
        with self.assertRaises(Exception):
            self.overflow.generate()


class TestSimpleRequestInit(unittest.TestCase):
    def test_invalid_host(self):
        with self.assertRaises(Exception):
            mow.SimpleRequest(12)

    def test_invalid_port(self):
        with self.assertRaises(Exception):
            mow.SimpleRequest('1.2.3.4', port='80')

    def test_invalid_request(self):
        with self.assertRaises(Exception):
            mow.SimpleRequest('1.2.3.4', request=12)

    def test_invalid_args(self):
        with self.assertRaises(Exception):
            mow.SimpleRequest('1.2.3.4', args=44)

    def test_default_params(self):
        sr = mow.SimpleRequest('1.2.3.4')
        self.assertEqual(sr.host, '1.2.3.4')
        self.assertEqual(sr.port, 80)
        self.assertIsNone(sr.request)
        self.assertIsNone(sr.args)

    def test_params(self):
        sr = mow.SimpleRequest('1.2.3.4', 500, 'apply.cgi', {'a': 'b'})
        self.assertEqual(sr.host, '1.2.3.4')
        self.assertEqual(sr.port, 500)
        self.assertEqual(sr.request, 'apply.cgi')
        self.assertEqual(sr.args, {'a': 'b'})


class TestCreateUrl(unittest.TestCase):
    def test_default_params(self):
        sr = mow.SimpleRequest('1.2.3.4')
        result = sr.create_url()
        self.assertEqual(result, 'http://1.2.3.4')

    def test_non_default_port(self):
        sr = mow.SimpleRequest('1.2.3.4', port=8080)
        result = sr.create_url()
        self.assertEqual(result, 'http://1.2.3.4:8080')

    def test_request_page(self):
        sr = mow.SimpleRequest('1.2.3.4', request='apply.cgi')
        result = sr.create_url()
        self.assertEqual(result, 'http://1.2.3.4/apply.cgi')

    def test_arguments(self):
        sr = mow.SimpleRequest('1.2.3.4', args={'color': 'red'})
        result = sr.create_url()
        self.assertEqual(result, 'http://1.2.3.4?color=red')

    def test_page_multiple_args(self):
        sr = mow.SimpleRequest('1.2.3.4', request='apply.cgi',
                               args={'ab': 'cd', 'ef': 'gh'})
        result = sr.create_url()
        self.assertEqual(result, 'http://1.2.3.4/apply.cgi?ab=cd&ef=gh')


class TestCustomRequestInit(unittest.TestCase):
    def test_invalid_host(self):
        with self.assertRaises(Exception):
            mow.CustomRequest(1, port=80, request_type=mow.GET,
                              request_dest='apply.cgi', headers={'a': 'b'},
                              data='')

    def test_invalid_port(self):
        with self.assertRaises(Exception):
            mow.CustomRequest('1.2.3.4', port='80', request_type=mow.GET,
                              request_dest='apply.cgi', headers={'a': 'b'},
                              data='')

    def test_invalid_request_type(self):
        with self.assertRaises(Exception):
            mow.CustomRequest('1.2.3.4', port=80, request_type='get',
                              request_dest='apply.cgi', headers={'a': 'b'},
                              data='')

    def test_invalid_request_dest(self):
        with self.assertRaises(Exception):
            mow.CustomRequest('1.2.3.4', port=80, request_type=mow.GET,
                              request_dest=5, headers={'a': 'b'},
                              data='')

    def test_invalid_headers(self):
        with self.assertRaises(Exception):
            mow.CustomRequest('1.2.3.4', port=80, request_type=mow.GET,
                              request_dest='a', headers='a=b',
                              data='')

    def test_invalid_data(self):
        with self.assertRaises(Exception):
            mow.CustomRequest('1.2.3.4', port=80, request_type=mow.GET,
                              request_dest='a', headers={'a': 'b'},
                              data=5)

    def test_values(self):
        cr = mow.CustomRequest('1.2.3.4', port=80, request_type=mow.GET,
                               request_dest='apply.cgi', headers={'a': 'b'},
                               data='')
        self.assertEqual(cr.host, b'Host: 1.2.3.4:80')
        self.assertEqual(cr.request, b'GET /apply.cgi HTTP/1.1')
        self.assertEqual(cr.headers, {'a': 'b'})
        self.assertEqual(cr.data, b'')

    def test_remove_slash(self):
        cr = mow.CustomRequest('1.2.3.4', port=80, request_type=mow.GET,
                               request_dest='/apply.cgi', headers={'a': 'b'},
                               data='')
        self.assertEqual(cr.request, b'GET /apply.cgi HTTP/1.1')


class TestCreatePacket(unittest.TestCase):
    def test_no_data(self):
        cr = mow.CustomRequest('1.2.3.4', port=80, request_type=mow.GET,
                               request_dest='apply.cgi',
                               headers={'a': 'b'}, data=None)

        packet = cr.create_packet()
        expected_result = b'GET /apply.cgi HTTP/1.1\r\n'
        expected_result += b'Host: 1.2.3.4:80\r\n'
        expected_result += b'a: b\r\n'
        expected_result += b'Content-Length: 0\r\n\r\n'
        self.assertEqual(packet, expected_result)

    def test_data(self):
        cr = mow.CustomRequest('1.2.3.4', port=80, request_type=mow.GET,
                               request_dest='apply.cgi',
                               headers={'a': 'b'}, data='data')

        packet = cr.create_packet()
        expected_result = b'GET /apply.cgi HTTP/1.1\r\n'
        expected_result += b'Host: 1.2.3.4:80\r\n'
        expected_result += b'a: b\r\n'
        expected_result += b'Content-Length: 4\r\n\r\n'
        expected_result += b'data'
        self.assertEqual(packet, expected_result)


if __name__ == '__main__':
    unittest.main()
