#!/usr/bin/env python3
# Read or write 8A34004 registers through /dev/rsmu0 (RSMU_REG_READ / RSMU_REG_WRITE).
# Writes go to the chip RAM only; the OTP configuration is reloaded on reboot.
#
#   rsmu_write.py <addr>                 read 1 byte
#   rsmu_write.py <addr> <n>             read n bytes (n <= 256, decimal)
#   rsmu_write.py <addr> -w <hex bytes>  write bytes, then read them back
#
# Example: rsmu_write.py 0x2010c1bd -w 01
import fcntl, os, struct, sys

S = 264
R = (2 << 30) | (S << 16) | (ord('?') << 8) | 100
W = (2 << 30) | (S << 16) | (ord('?') << 8) | 101


def usage():
    sys.exit(__doc__ if __doc__ else 'usage: rsmu_write.py <addr> [n | -w <hex bytes>]')


if len(sys.argv) < 2:
    usage()
addr = int(sys.argv[1], 0)
fd = os.open('/dev/rsmu0', os.O_RDWR)


def rd(n):
    return bytes(fcntl.ioctl(fd, R, struct.pack('IB', addr, n).ljust(S, b'\0'))[5:5 + n])


if len(sys.argv) >= 4 and sys.argv[2] == '-w':
    data = bytes.fromhex(''.join(sys.argv[3:]))
    fcntl.ioctl(fd, W, (struct.pack('IB', addr, len(data)) + data).ljust(S, b'\0'))
    print(f'0x{addr:08x} <- {data.hex(" ")}  readback {rd(len(data)).hex(" ")}')
else:
    n = int(sys.argv[2]) if len(sys.argv) >= 3 else 1
    print(f'0x{addr:08x}: {rd(n).hex(" ")}')
