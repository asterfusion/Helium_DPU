#!/usr/bin/env python3
# SyncE status and DPLL5 lock check for the 8A34004, through /dev/rsmu0.
#
#   synce_state.py [label]        print IN0 signal / frequency offset and DPLL5 / DPLL6 / SYS state
#   synce_state.py check_locked   exit 0 if DPLL5 is LOCKED, 1 otherwise
import fcntl, os, struct, sys, time

S = 264
R = (2 << 30) | (S << 16) | (ord('?') << 8) | 100
fd = os.open('/dev/rsmu0', os.O_RDONLY)
N = {0: 'FREERUN', 1: 'LOCKACQ', 2: 'LOCKREC', 3: 'LOCKED', 4: 'HOLDOVER', 5: 'OPEN_LOOP', 6: 'DISABLED'}


def rd(a, n):
    return bytes(fcntl.ioctl(fd, R, struct.pack('IB', a, n).ljust(S, b'\0'))[5:5 + n])


arg = sys.argv[1] if len(sys.argv) > 1 else ''
if arg == 'check_locked':
    sys.exit(0 if rd(0x2010c03c + 0x1d, 1)[0] & 0x0f == 3 else 1)
else:
    b = rd(0x2010c03c, 0x90)
    v = b[0x8c] | (b[0x8d] << 8)
    f = v & 0x3fff
    if f & 0x2000:
        f -= 0x4000
    f = f * {0: 1, 1: 10, 2: 100, 3: 1000}[v >> 14] / 1000.0
    print(f'{time.strftime("%T")} {arg:<26} IN0 {"LOS" if b[8] & 1 else "sig"} {f:+.3f}ppm '
          f'DPLL5 {N.get(b[0x1d] & 15)} DPLL6 {N.get(b[0x1e] & 15)} SYS {N.get(b[0x20] & 15)}', end='')
