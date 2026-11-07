#!/usr/bin/env python3
# Read-only dump of the 8A34004 configuration (OTP / active) via /dev/rsmu0.
# Register map: include/linux/mfd/idt8a340_reg.h, FW < 5.2 (non-V520 offsets).
# Field layouts not in the header (INPUT_x) follow the 8A3400x programming
# guide and are printed raw as well, so they can be re-checked.
import fcntl, os, struct, sys

SIZE = 264
REG_READ = (2 << 30) | (SIZE << 16) | (ord('?') << 8) | 100
fd = os.open(sys.argv[1] if len(sys.argv) > 1 else '/dev/rsmu0', os.O_RDONLY)

def rd(addr, n):
    buf = struct.pack('IB', addr, n).ljust(SIZE, b'\0')
    return bytes(fcntl.ioctl(fd, REG_READ, buf)[5:5 + n])

def le(b):
    return int.from_bytes(b, 'little')

def hx(b):
    return ' '.join(f'{x:02x}' for x in b)

INPUT = [0x2010c1b0, 0x2010c1c0, 0x2010c1d0, 0x2010c200, 0x2010c210, 0x2010c220,
         0x2010c230, 0x2010c240, 0x2010c250, 0x2010c260, 0x2010c280, 0x2010c290,
         0x2010c2a0, 0x2010c2b0, 0x2010c2c0, 0x2010c2d0]
DPLL = [0x2010c3b0, 0x2010c400, 0x2010c438, 0x2010c480, 0x2010c4b8, 0x2010c500,
        0x2010c538, 0x2010c580]
DPLL_CTRL = [0x2010c600, 0x2010c63c, 0x2010c680, 0x2010c6bc, 0x2010c700,
             0x2010c73c, 0x2010c780, 0x2010c7bc]
OUTPUT = [0x2010ca14, 0x2010ca24, 0x2010ca34, 0x2010ca44, 0x2010ca54, 0x2010ca64,
          0x2010ca80, 0x2010ca90, 0x2010caa0, 0x2010cab0, 0x2010cac0, 0x2010cad0]
STATUS = 0x2010c03c
OUT_DIV_MUX = 0x2010ca12
GEN = 0x2010c014

g = rd(GEN, 0x24)
print(f'FW {g[0x10] >> 1}.{g[0x11]}.{g[0x12]}  product 0x{le(g[0x1e:0x20]):04x}  '
      f'otp_cfg_sel 0x{g[0x22]:02x}')

st = rd(STATUS, 0x30)
mon, dst, rst = st[0x08:0x18], st[0x18:0x20], st[0x22:0x2a]
NAMES = {0: 'FREERUN', 1: 'LOCKACQ', 2: 'LOCKREC', 3: 'LOCKED', 4: 'HOLDOVER',
         5: 'OPEN_LOOP', 6: 'DISABLED'}

print('\n== INPUT  (freq = M / N; IN_MODE bit0 = enable)')
print('in  mon  raw[0:16]                                        M            N     DIV   MODE  freq(Hz)')
for i, a in enumerate(INPUT):
    b = rd(a, 16)
    m, n, div, mode = le(b[0:6]), le(b[6:8]), le(b[8:10]), b[0x0d]
    f = m / (n if n else 1)
    print(f'{i:<3} {mon[i]:02x}   {hx(b)}  {m:<12} {n:<5} {div:<5} {mode:02x}    {f:,.3f}')

print('\n== DPLL   (REF_PRIORITY: bit0 enable, bits[5:1] input)')
for i, a in enumerate(DPLL):
    b = rd(a, 0x38)
    pri = []
    for k in range(0x0f, 0x22):
        v = b[k]
        if v & 1:
            pri.append(f'IN{(v >> 1) & 0x1f}')
    print(f'DPLL{i}: status {dst[i]:02x} {NAMES.get(dst[i] & 0xf, "?"):<9} '
          f'ref_status {rst[i]:02x}  CTRL_REG {hx(b[2:5])}  REF_MODE {b[0x35]:02x}  '
          f'PHASE_MEAS {b[0x36]:02x}  MODE {b[0x37]:02x}  priority [{", ".join(pri)}]')

print('\n== DPLL_CTRL  (FOD freq = M / N)')
for i, a in enumerate(DPLL_CTRL):
    b = rd(a, 0x24)
    m, n = le(b[0x1c:0x22]), le(b[0x22:0x24])
    f = m / (n if n else 1)
    print(f'DPLL{i}: MANU_REF_CFG {b[1]:02x}  FOD M {m}  N {n}  -> {f:,.3f} Hz')

print(f'\n== OUT_DIV_MUX {rd(OUT_DIV_MUX, 2).hex()}')
print('== OUTPUT  (out freq = FOD freq / OUT_DIV)')
for i, a in enumerate(OUTPUT):
    b = rd(a, 16)
    print(f'Q{i:<2} OUT_DIV {le(b[0:4]):<10} DUTY_HIGH {le(b[4:8]):<10} '
          f'CTRL_0 {b[8]:02x} CTRL_1 {b[9]:02x}  raw {hx(b)}')
