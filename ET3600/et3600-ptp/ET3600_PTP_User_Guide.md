# ET3600 PTP User Guide

This guide describes how to run IEEE 1588 PTP on the ET3600 as a Boundary Clock (BC)
or a Transparent Clock (TC) and how to verify it. It covers both port types:

- **X ports** (X1, X2): 10G SFP+, connected directly to the CN103 SoC.
- **C ports** (C1, C2): 100G QSFP28 behind an 88X6141 PHY; can be split (breakout)
  into C1-1 / C1-2 / C2-1 / C2-2.

This guide covers functional operation; timing accuracy tuning is not covered.

### Verified functions

All functions below were tested on hardware. The downstream slave in the tests was a
Linux server with an `mlx5` 10/25G NIC (hardware timestamping), running `ptp4l -2 -s`.

| Function | Profile | Upstream port | Downstream port |
|---|---|---|---|
| BC, single instance (sec. 4), incl. upstream failure | default 1588, L2 | X1 | C2-1, X2 |
| TC, E2E (sec. 5) | default 1588, L2 | X1 | C2-1, X2 |
| BC upstream (sec. 6.1–6.2) | G.8275.2, UDPv4 unicast | X1 or C1-1 | — |
| BC redundant upstream (sec. 6.3) | G.8275.2 | X1 + C1-1 | — |
| BC two instances (sec. 6.4) | G.8275.2 up / 1588 down | X1 + C1-1 | C2-1 |
| SyncE, C port at 10G (sec. 7) | — | C1-1, C2-1 | SerDes reference |

---

## 1. Architecture

### 1.1 Timestamping

PTP event messages are timestamped by the CN103 MAC. All CN103 ports share **one**
hardware PTP counter, exposed as several `/dev/ptpN` nodes (one per port). Adjusting
any of them adjusts all of them. Consequences:

- Use `boundary_clock_jbod 1` whenever one `ptp4l` instance uses more than one port.
- Run only **one** `ptp4l` instance that adjusts the clock at a time. Do not run the
  BC and TC configurations together.

The CN103 PTP counter runs from the CN103 internal clock. It does not depend on the
PTP daughter card.

### 1.2 PTP daughter card (Renesas 8A34004)

| Item | Value |
|---|---|
| Device | Renesas 8A34004 ClockMatrix |
| Bus | i2c-0 → PCA9548 @0x71 channel 4 (Linux `i2c-10`), address `0x58` |
| Drivers | `rsmu_core`, `rsmu_i2c`, `ptp_clockmatrix`, `rsmu` |
| Linux devices | one PHC named `IDT CM TOD2`, and `/dev/rsmu0` |
| Configuration | stored in the chip OTP; no `idtcm.bin` firmware file is required |

The daughter card is the frequency source for SyncE (see section 7). It is **not**
part of the PTP timestamp path in this release.

> **Note:** the bit meaning of CPLD `0x2C` bit1 is inverted compared with the CPLD
> manual (0 = C1). See section 7.2.

### 1.3 Port to PHC mapping

PHC numbers depend on the port mode. With C1/C2 in breakout mode:

| Port | PHC |
|---|---|
| X2 | ptp0 |
| X1 | ptp1 |
| C2-1 | ptp2 |
| C2-2 | ptp3 |
| C1-1 | ptp4 |
| C1-2 | ptp5 |
| 8A34004 (TOD2) | ptp6 (only after the chip is bound) |

Always confirm the mapping on the running system:

```sh
for i in X1 X2 C1-1 C1-2 C2-1 C2-2; do
  echo "$i $(ethtool -T $i | awk -F': ' '/PTP Hardware Clock/{print $2}')"
done
for p in /sys/class/ptp/ptp*; do echo "$p $(cat $p/clock_name)"; done
```

---

## 2. Prerequisites

### 2.1 Software

- Kernel 6.6.46 with the Renesas RSMU / ClockMatrix drivers
  (`CONFIG_MFD_RSMU_I2C=m`, `CONFIG_PTP_1588_CLOCK_IDTCM=m`, `CONFIG_RSMU=m`)
- linuxptp 3.1.1 or later (`ptp4l`, `pmc`, `phc_ctl`)
- `ethtool`, `iproute2`, `i2c-tools`; `tcpdump` is recommended for troubleshooting

### 2.2 Bring up the ports

After every reboot the data ports are administratively down and have no IP address.
Bring up the ports you use:

```sh
ip link set X1 up
ip link set C2-1 up
```

The default 1588 profile runs over Layer 2 and needs no IP address. The G.8275.2
profile (section 6) runs over UDPv4 and needs one:

```sh
ip addr replace 10.25.1.2/24 dev X1
ip addr replace 10.25.3.2/24 dev C1-1
```

Check that the link is up and that the port supports hardware timestamping:

```sh
ethtool X1 | grep -E 'Speed|Link detected'
ethtool -T X1      # needs hardware-transmit, hardware-receive, hardware-raw-clock
```

### 2.3 Bind the 8A34004 (optional for PTP, required for SyncE)

The device tree does not describe the 8A34004, because the PTP daughter card is
optional. On a system with the card installed, bind the chip manually after every
reboot. First check that the card is present:

```sh
i2cget -y 4 0x40 0x0d    # bit2 = 0: PTP card present
```

Bind the chip only when the card is present:

```sh
echo 8a34001 0x58 > /sys/bus/i2c/devices/i2c-10/new_device
dmesg | grep -iE '8a340|idtcm|rsmu'
```

Expected messages:

```
8a3400x-phc 8a3400x-phc.0.auto: 4.8.8, Id: 0x4004  HW Rev: 5  OTP Config Select: 0
8a3400x-phc 8a3400x-phc.0.auto: loading firmware failed with -2     <- expected, no idtcm.bin
rsmu-cdev 8a3400x-cdev.1.auto: Probe rsmu0 successful
8a3400x-phc 8a3400x-phc.0.auto: PLL2 registered as ptp6
```

> **Warning:** Do not run `delete_device` on `10-0058` and do not `rmmod rsmu_i2c`.
> Unbinding currently triggers a kernel oops in the regmap debugfs teardown.
> To change or reload the drivers, reboot the system.

---

## 3. Grandmaster requirements

### 3.1 Default 1588 profile (sections 4 and 5)

| Parameter | Value |
|---|---|
| Profile | IEEE 1588 default (delay request-response) |
| Domain | 0 |
| Transport | Ethernet (L2), multicast `01:1B:19:00:00:00` |
| Delay mechanism | E2E |
| Clock step | two-step |

### 3.2 G.8275.2 profile (section 6)

| Parameter | Value |
|---|---|
| Profile | G.8275.2 (PTP over IPv4, unicast negotiation) |
| Domain | 2 |
| Transport | UDPv4 |
| Delay mechanism | E2E |
| Clock type | T-GM, two-step |
| Announce interval | 2^-3 s |
| Sync / Delay_Req interval | 2^-4 s |

The GM port must accept unicast negotiation from the ET3600 port address (one GM port
per ET3600 link). The examples in section 6 use:

| ET3600 port | ET3600 address | GM address |
|---|---|---|
| X1 | 10.25.1.2/24 | 10.25.1.1 |
| C1-1 | 10.25.3.2/24 | 10.25.3.1 |

---

## 4. Boundary Clock (default 1588 profile)

One `ptp4l` instance manages all ports. The Best Master Clock Algorithm (BMCA) puts
the port that receives the best grandmaster into SLAVE and the other ports into
MASTER. Any port can be upstream or downstream; no per-port role is configured.

Configuration file: `configs/bc-1588.cfg`

```ini
[global]
domainNumber            0
network_transport       L2
time_stamping           hardware
delay_mechanism         E2E
boundary_clock_jbod     1
priority1               128
priority2               128
tx_timestamp_timeout    50
summary_interval        0
logging_level           6
uds_address             /var/run/ptp4l-bc
```

Run (list every port in use):

```sh
ptp4l -f bc-1588.cfg -i X1 -i C2-1 -m
```

Expected output on the ET3600:

```
port 1: new foreign master <GM clock id>-1
selected best master clock <GM clock id>
port 1: LISTENING to UNCALIBRATED on RS_SLAVE
port 2: LISTENING to MASTER on ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES
port 1: UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED
```

Check that the grandmaster is passed downstream:

```sh
pmc -u -b 0 -s /var/run/ptp4l-bc 'GET PARENT_DATA_SET' 'GET CURRENT_DATA_SET'
# grandmasterIdentity  = upstream GM
# stepsRemoved         = 1
```

On a downstream slave, the foreign master is the ET3600 port
(`<ET3600 clock id>-2`) and the selected grandmaster is the upstream GM.

Verified result (X1 upstream; downstream on C2-1 and on X2, both 10G):

| Item | Result |
|---|---|
| ET3600 X1 | SLAVE about 10 s after start |
| Downstream slave on C2-1 | SLAVE about 8 s after start; GM = upstream GM; offset within ±60 ns; path delay about 355 ns |
| Downstream slave on X2 | SLAVE about 5 s after start; GM = upstream GM; offset within ±55 ns; path delay about 235 ns |

The C port path delay is about 120 ns longer than the X port because of the 88X6141 PHY.

Upstream failure (X1 link down for 40 s):

| Event | ET3600 | Downstream slave |
|---|---|---|
| X1 link down | X1 FAULTY; ET3600 becomes grandmaster (own clock identity, clockClass 248) | Switches GM to the ET3600 within about 1 s; stays SLAVE; no time step |
| X1 link restored | X1 back to SLAVE after about 8 s | Switches GM back to the upstream GM; max offset a few hundred ns during re-lock |

---

## 5. Transparent Clock (E2E, default 1588 profile)

The TC forwards PTP messages between its ports and adds the residence time to the
`correctionField`. It also syntonizes the CN103 counter to the grandmaster, so it
must not run together with any BC instance.

The linuxptp TC only forwards multicast messages: ptp4l does not receive unicast
messages addressed to other hosts, and it forwards every message to the PTP
multicast address. The upstream GM must therefore use multicast (for example the
default 1588 profile, section 3.1); G.8275.2 unicast does not work through the
ET3600 TC. When the upstream GM only offers G.8275.2, use a BC (section 6).

Configuration file: `configs/tc-e2e-1588.cfg`

```ini
[global]
clock_type              E2E_TC
domainNumber            0
network_transport       L2
time_stamping           hardware
delay_mechanism         E2E
boundary_clock_jbod     1
tx_timestamp_timeout    50
summary_interval        0
logging_level           6
uds_address             /var/run/ptp4l-tc
```

```sh
ptp4l -f tc-e2e-1588.cfg -i X1 -i C2-1 -m
```

Verified result (GM on X1; slave on C2-1, then on X2):

| Item | X1 → C2-1 | X1 → X2 |
|---|---|---|
| Forwarded Sync / Follow_Up / Announce | Source clock identity is the GM | same |
| Follow_Up `correctionField` (residence time; linuxptp forwards in software) | about 45 µs | about 21–25 µs |
| Downstream slave | SLAVE after about 8 s; GM = upstream GM; offset within ±53 ns | SLAVE after about 8 s; GM = upstream GM; offset within ±50 ns |
| Downstream path delay (sum of both links) | about 630 ns | about 510 ns |

---

## 6. Alternative: G.8275.2 upstream

Use this when the upstream GM only offers G.8275.2 (PTP over IPv4, unicast). The
ports need IP addresses (section 2.2).

### 6.1 X port as upstream

Configuration file: `configs/bc-upstream-g8275.2.cfg`

```ini
[global]
domainNumber            2
network_transport       UDPv4
time_stamping           hardware
delay_mechanism         E2E
slaveOnly               1
dataset_comparison      G.8275.x
G.8275.defaultDS.localPriority  128
logSyncInterval         -4
logMinDelayReqInterval  -4
logAnnounceInterval     -3
announceReceiptTimeout  3
tx_timestamp_timeout    50
uds_address             /var/run/ptp4l-upstream
unicast_req_duration    60

[unicast_master_table]
table_id                1
logQueryInterval        2
UDPv4                   10.25.1.1

[X1]
unicast_master_table    1
```

```sh
ptp4l -f bc-upstream-g8275.2.cfg -i X1 -m
```

Verified result: SLAVE about 8 s after start; offset rms 2–5 ns; path delay 267 ns.

### 6.2 C port as upstream

Configuration file: `configs/bc-upstream-g8275.2-c1.cfg`. It is the same as 6.1,
except for the master address and the port section:

```ini
[unicast_master_table]
table_id                1
logQueryInterval        2
UDPv4                   10.25.3.1

[C1-1]
unicast_master_table    1
```

```sh
ptp4l -f bc-upstream-g8275.2-c1.cfg -i C1-1 -m
```

Verified result (C1 in breakout mode, C1-1 at 10G): SLAVE about 8 s after start;
offset rms 2–5 ns; path delay 394 ns. The extra ~127 ns compared with the X port is
the fixed latency of the 88X6141 PHY. No PHY configuration change is required for
functional operation.

### 6.3 Redundant upstream (X port + C port)

Configuration file: `configs/bc-upstream-g8275.2-x1-c1.cfg`. Both ports are in one
`ptp4l` instance, each with its own unicast master table:

```ini
[global]
...
slaveOnly               1
boundary_clock_jbod     1
...
[unicast_master_table]
table_id                1
logQueryInterval        2
UDPv4                   10.25.1.1

[unicast_master_table]
table_id                3
logQueryInterval        2
UDPv4                   10.25.3.1

[X1]
unicast_master_table    1

[C1-1]
unicast_master_table    3
```

```sh
ptp4l -f bc-upstream-g8275.2-x1-c1.cfg -i X1 -i C1-1 -m
```

Verified behavior:

| Event | X1 | C1-1 |
|---|---|---|
| Both links up | SLAVE | LISTENING (standby) |
| X1 link down | FAULTY | becomes SLAVE within about 4 s |
| X1 link restored | SLAVE again within about 4 s | LISTENING |

There is no time step during switchover; offset rms stays within 1–6 ns.
A 10.5-minute run had no faults or timeouts (rms mean 3 ns, |offset| max 13 ns).

The message `master state recommended in slave only mode` is expected with
`slaveOnly 1` on multiple ports and can be ignored.

### 6.4 Two instances: G.8275.2 upstream, 1588 downstream

When the upstream and downstream profiles differ, run a second `ptp4l` instance for
the downstream ports. It only reads the counter that the upstream instance
disciplines (`free_running 1`, `masterOnly 1`).

Configuration file: `configs/bc-downstream-1588.cfg`

```sh
# upstream instance (6.1 / 6.2 / 6.3) must already be running
ptp4l -f bc-downstream-1588.cfg -i C2-1 -m
```

Verified result (C2-1): the downstream slave locks within about 4 s, offset within
±52 ns, while the upstream instance stays locked.

Limitations — prefer section 4 when one profile can be used end to end:

- The downstream instance announces the ET3600 itself as grandmaster with a fixed
  `clockClass 6`. The upstream GM identity, its clockClass and `stepsRemoved` are
  not passed downstream.
- If the upstream is lost, the downstream instance keeps announcing `clockClass 6`.

---

## 7. SyncE (C port, 10G)

SyncE recovers the line frequency from an upstream C port and makes the PTP card
(8A34004) generate the SerDes / PHY 156.25 MHz reference from it.

Supported upstream ports: C1-1 and C2-1 at 10G.

### 7.1 Clock path

```
upstream ──► C1 port ──► 88X6141 (C1) RCLK B ─┐ CLK_OUT_SE1
                         88X6141 (C2) RCLK B ─┴─► 2:1 switch (CPLD 0x2C bit1) ──► 8A34004 CLK0 (IN0, single-ended)
                                                                                      │
              DPLL5 (SyncE DPLL, locks to IN0) ──combo bus──► DPLL6 (DCO) ──► Q10 156.25 MHz
                                                                                      │
              Clock buffer (CPLD 0x2C bit0) ──► CN103 SerDes + both 88X6141 reference ◄┘
```

| Item | Value |
|---|---|
| 6141 recovered clock | Line side, lane 0, divided to 40.283203125 MHz |
| 8A34004 input | IN0 (CLK0), **single-ended**, expected 40.283203125 MHz |
| SyncE DPLL | DPLL5 (automatic, priority IN0 > IN1, FOD 500 MHz → Q8 1PPS, Q9 25 MHz) |
| SerDes reference | Q10 = DPLL6 FOD 625 MHz ÷ 4 = 156.25 MHz (Q11 = 25 MHz) |
| PTP PHC (`IDT CM TOD2`) | DPLL2, write-frequency DCO, no output pin |

The 8A34004 has three channels (DPLL2, DPLL5, DPLL6), two inputs (CLK0/nCLK0,
CLK1/nCLK1) and four outputs (Q8–Q11). There is no 125 MHz output in the current OTP.

### 7.2 Differences from the OTP and the CPLD manual

| Item | Document / OTP | Actual (measured) | Action |
|---|---|---|---|
| CPLD `0x2C` bit1 | 1 = first 6141 = C1 | **0 = C1** (6141 at `eth=2 lmac=2`), 1 = C2 (`eth=2 lmac=0`) | Use bit1 = 0 for C1 |
| 8A34004 IN0 mode | Differential (`IN_MODE` 0x21) | Switch output is single-ended on CLK0 | Set `IN_MODE` = 0x01 |
| 6141 RCLK mux / divider | Not configured by the SDK (divider off) | Must be configured | Write F426 / F422 (7.3 step 1) |
| DPLL6 combo source | Primary = system DPLL (XO) | Must follow DPLL5 | Set primary = DPLL5 (7.3 step 4) |

### 7.3 Configuration (C1-1 or C2-1 at 10G)

Use the column that matches the upstream C port:

| Item | C1 upstream | C2 upstream |
|---|---|---|
| 6141 selection (`phy_diag`) | `echo "2 2" > $D/phy` | `echo "2 0" > $D/phy` |
| CPLD `0x2C`, SerDes on XO (step 2) | `0x01` | `0x03` |
| CPLD `0x2C`, SerDes on PTP card (step 6) | `0x00` | `0x02` |

The commands below show C1; for C2 replace the three values above.

All settings are runtime only and are lost on reboot. Run them in this order after the
port is up and the 8A34004 is bound (section 2.3). Helper scripts are in `scripts/`.

```sh
# 1. 88X6141 (C1) recovered clock: line side, lane 0, 32/16T source, divider /16 = 40.283 MHz
D=/sys/kernel/debug/phy_diagnostics          # needs phy_diag.ko and debugfs
echo "2 2" > $D/phy                          # C1 PHY  (C2 PHY: "2 0")
echo "c45 31 f426 0044" > $D/write_reg       # RCLK top-level mux
echo "c45 31 f422 0721" > $D/write_reg       # line RCLK ctrl: src=1, lane 0, divider on, ratio 7 (/16)

# 2. CPLD: route C1 RCLK to the PTP card (bit1 = 0), SerDes reference still on XO (bit0 = 1)
i2cset -y 4 0x40 0x2c 0x01

# 3. 8A34004 IN0 single-ended + enabled (INPUT_0.IN_MODE, writing it re-applies INPUT_0)
python3 -I rsmu_write.py 0x2010c1bd -w 01

# 4. DPLL6 follows DPLL5 (DPLL_6.DPLL_COMBO_SLAVE_CFG_0 = 0x25), then trigger with DPLL_MODE
python3 -I rsmu_write.py 0x2010c56a -w 25
python3 -I rsmu_write.py 0x2010c56f -w 08

# 5. Wait for DPLL5 LOCKED (normally < 10 s)
python3 -I synce_state.py status; echo
python3 -I synce_state.py check_locked && echo LOCKED

# 6. Only when DPLL5 is LOCKED: SerDes / PHY reference from the PTP card (bit0 = 0)
i2cset -y 4 0x40 0x2c 0x00
```

> **CPLD rule:** set `0x2C` bit0 to 0 only while DPLL5 is LOCKED. If SyncE is lost
> for a longer time, set it back to 1 (`i2cset -y 4 0x40 0x2c 0x01`).

6141 register `31.F422` (line side recovered clock control, from the MYD API):

| Bits | Field | Value used |
|---|---|---|
| 0 | Source clock select | 1 |
| 2:1 | Lane | 0 |
| 5:4 | Divider enable (`10` = enable after the clock is ready) | `10` |
| 15:8 | Divide ratio, divider = 2 × (ratio + 1) | 7 → /16 |

At 10G the selected source is 644.53125 MHz, so /16 gives 40.283203125 MHz.

### 7.4 Verification

```sh
python3 -I synce_state.py status; echo
# expected: IN0 sig +0.0xx ppm  DPLL5 LOCKED  DPLL6 OPEN_LOOP  SYS LOCKED
python3 -I rsmu_cfg.py | grep -E 'DPLL5|DPLL6'
i2cget -y 4 0x40 0x2c          # 0x00 when the SerDes reference is on the PTP card
```

- `IN0 ... ppm` is the frequency offset of the recovered clock measured by the 8A34004.
  `+8191` / `-8192` means out of range (wrong divider, wrong CPLD bit1, or IN0 still
  differential).
- DPLL6 always reports `OPEN_LOOP`; this is normal for a DCO channel that follows DPLL5
  over the combo bus.

Verified result (C1-1 and C2-1, 10G):

| Step | Result |
|---|---|
| IN0 frequency offset | +0.009 ppm |
| DPLL5 | LOCKED within 5 s |
| `0x2C` bit0 → 0 | DPLL5 briefly LOCKREC (about 10 s, the 6141 reference also changes), then LOCKED; X1 / X2 / C1-1 stay up, no packet loss on ping |
| Switch back to bit0 = 1 | Links stay up |
| C2-1 upstream (6141 `eth=2 lmac=0`, `0x2C` = 0x03 → 0x02) | IN0 +0.009 ppm, DPLL5 LOCKED; after bit0 = 0 DPLL5 stays LOCKED, X1 / X2 / C2-1 up, ping OK |
| PTP BC (section 4) with SerDes reference on the PTP card | Unchanged: ET3600 offset ±15 ns, frequency −5070 ppb (CN103 PTP counter is not derived from the SerDes reference); downstream slave on X2 locks to the GM, offset ±65 ns |

### 7.5 Revert

```sh
i2cset -y 4 0x40 0x2c 0x03                     # SerDes reference back to XO, CPLD default
python3 -I rsmu_write.py 0x2010c56a -w 28      # DPLL6 combo primary back to system DPLL
python3 -I rsmu_write.py 0x2010c56f -w 08
python3 -I rsmu_write.py 0x2010c1bd -w 21      # IN0 back to OTP value (differential)
echo "2 2" > $D/phy
echo "c45 31 f422 0000" > $D/write_reg
echo "c45 31 f426 0000" > $D/write_reg
```

Or reboot: the 8A34004 reloads its OTP, the CPLD returns to `0x03`.

### 7.6 Useful 8A34004 addresses (FW 4.8)

| Register | Address |
|---|---|
| STATUS (IN mon status +0x08, DPLL status +0x18, IN FFO +0x8C) | 0x2010c03c |
| INPUT_0.IN_MODE | 0x2010c1bd |
| INPUT_1.IN_MODE | 0x2010c1cd |
| DPLL_5 (REF_MODE +0x35, DPLL_MODE +0x37) | 0x2010c500 |
| DPLL_6.DPLL_COMBO_SLAVE_CFG_0 / _1 | 0x2010c56a / 0x2010c56b |
| DPLL_6.DPLL_MODE | 0x2010c56f |

Register details: `reference/renesas/8A3xxxx-Family-Programming-Guide-v4.8.pdf`.
CPLD registers can be read with `i2cget -y 4 0x40 <reg>`:

```sh
i2cget -y 4 0x40 0x0d    # bit2 = 0: PTP card present
i2cget -y 4 0x40 0x2c    # bit1: RCLK select (0 = C1, 1 = C2), bit0: SerDes reference (0 = PTP card)
```

---

## 8. Monitoring

Use the `uds_address` of the running configuration with `-s`, and add `-d 2` for
the G.8275.2 instances (domain 2):

| Configuration | Socket |
|---|---|
| `bc-1588.cfg` | `/var/run/ptp4l-bc` |
| `tc-e2e-1588.cfg` | `/var/run/ptp4l-tc` |
| `bc-upstream-g8275.2*.cfg` | `/var/run/ptp4l-upstream` (`-d 2`) |
| `bc-downstream-1588.cfg` | `/var/run/ptp4l-downstream` |

```sh
S=/var/run/ptp4l-bc
pmc -u -b 0 -s $S 'GET PORT_DATA_SET'      # port states
pmc -u -b 0 -s $S 'GET CURRENT_DATA_SET'   # offsetFromMaster, stepsRemoved
pmc -u -b 0 -s $S 'GET PARENT_DATA_SET'    # grandmaster identity and quality
```

---

## 9. Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| `new foreign master` is printed once, then `selected local clock ... as best master` repeats every few seconds (G.8275.2) | Announce interval mismatch. The GM grants the requested rate but writes its own configured interval (-3) into the Announce header; ptp4l then rejects the master. | Set `logAnnounceInterval` to the GM's configured Announce interval (`-3` in `configs/bc-upstream-g8275.2*.cfg`). |
| Downstream slave sees no TC-forwarded messages | GM uses unicast (G.8275.2). The linuxptp TC only forwards multicast. | Use a multicast profile on the GM, or use a BC (section 6) for a G.8275.2 upstream. |
| Offsets jump, or two instances fight over the clock | BC and TC (or two BC upstream instances) running at the same time on the shared counter | Run one adjusting instance only (section 1.1). |
| `loading firmware failed with -2` for the 8A34004 | No `idtcm.bin`; configuration is in OTP | Expected, ignore. |
| SyncE: IN0 offset reads `+8191` / `-8192` ppm, DPLL5 stays LOCKACQ | IN0 still differential, wrong CPLD `0x2C` bit1, or 6141 RCLK divider not set | Section 7.3 steps 1–3; bit1 = 0 for C1 |
| SyncE: IN0 LOS | The selected 6141 has no RCLK output (divider off) or CPLD bit1 selects the other PHY | Configure F426/F422 on the PHY selected by bit1 |
| SyncE: DPLL5 does not lock although IN0 has a signal | The upstream partner's frequency is far off (for example a server NIC at about 18 ppm), outside the SyncE pull-in range | Use a SyncE-capable upstream device. |
| All SerDes links drop after `0x2C` bit0 = 0 | PTP card output not valid (DPLL5 not locked / card not configured) | `i2cset -y 4 0x40 0x2c 0x01`; switch only when DPLL5 is LOCKED |

---

## 10. Files

| File | Purpose |
|---|---|
| `configs/bc-1588.cfg` | BC, single instance, default 1588 (section 4) |
| `configs/tc-e2e-1588.cfg` | E2E TC, default 1588 (section 5) |
| `configs/bc-upstream-g8275.2.cfg` | G.8275.2 upstream on X1 (6.1) |
| `configs/bc-upstream-g8275.2-c1.cfg` | G.8275.2 upstream on C1-1 (6.2) |
| `configs/bc-upstream-g8275.2-x1-c1.cfg` | G.8275.2 redundant upstream on X1 + C1-1 (6.3) |
| `configs/bc-downstream-1588.cfg` | Downstream instance for the two-instance BC (6.4) |
| `scripts/rsmu_cfg.py` | Read-only 8A34004 configuration dump |
| `scripts/rsmu_write.py` | 8A34004 register read / write (RAM only) |
| `scripts/synce_state.py` | SyncE status, DPLL5 lock check |
