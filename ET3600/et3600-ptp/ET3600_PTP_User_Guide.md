# ET3600 PTP User Guide

This guide describes how to run IEEE 1588 PTP on the ET3600 as a Boundary Clock (BC)
or a Transparent Clock (TC) and how to verify it. It covers both port types:

- **X ports** (X1, X2): 10G SFP+, connected directly to the CN103 SoC.
- **C ports** (C1, C2): 100G QSFP28 behind an 88X6141 PHY; can be split (breakout)
  into C1-1 / C1-2 / C2-1 / C2-2. Port names and PHC numbers depend on the port mode
  (section 1.3).

This guide covers functional operation; timing accuracy tuning is not covered.

### Verified functions

All functions below were tested on hardware. Measured results are in section 10.

| Function | Profile | Upstream port | Downstream port |
|---|---|---|---|
| BC, single instance (sec. 4), incl. upstream failure | default 1588, L2 | X1 | C2-1, X2 |
| TC, E2E (sec. 5) | default 1588, L2 | X1 | C2-1, X2 |
| BC upstream (sec. 6.1–6.2) | G.8275.2, UDPv4 unicast | X1 or C1-1 | — |
| BC redundant upstream (sec. 6.3) | G.8275.2 | X1 + C1-1 | — |
| BC two instances (sec. 6.4) | G.8275.2 up / 1588 down | X1 + C1-1 | C2-1 |
| SyncE at 10G (sec. 7.3, 7.4) | — | C1-1, C2-1, X1, X2 | SerDes reference |
| SyncE, C port + X port redundant (sec. 7.5) | — | C1-1 + X1 | SerDes reference |

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

PHC numbers depend on the port mode. With C1 and C2 in breakout mode
(2 ports each), the tested mapping is:

| Port | PHC |
|---|---|
| X2 | ptp0 |
| X1 | ptp1 |
| C2-1 | ptp2 |
| C2-2 | ptp3 |
| C1-1 | ptp4 |
| C1-2 | ptp5 |
| 8A34004 (TOD2) | ptp6 (only with the PTP card installed) |

Always confirm the mapping on the running system:

```sh
for i in X1 X2 C1-1 C1-2 C2-1 C2-2; do
  echo "$i $(ethtool -T $i | awk -F': ' '/PTP Hardware Clock/{print $2}')"
done
for p in /sys/class/ptp/ptp*; do echo "$p $(cat $p/clock_name)"; done
```

> **Note:** the C ports can run as 1x100G or be split into two ports (`portctl`, takes
> effect after a cold reboot). The port mode changes the interface names and the PHC
> numbering. This guide uses C1 and C2 in breakout mode with Cx-1 at 10G; with another
> mode, check the interface names (`ip -br link`) and the mapping above first.

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

### 2.3 8A34004 driver (optional for PTP, required for SyncE)

The Linux device tree (`et3600-linux.dts`) describes the 8A34004 at address `0x58`
on PCA9548 `0x71` channel 4 (`i2c-10`), compatible `idt,8a34001`. The kernel binds
the chip at boot and loads `rsmu_i2c`, `ptp_clockmatrix` and `rsmu`
automatically; no manual step is needed.

Check that the card is present and the chip is bound:

```sh
i2cget -y 4 0x40 0x0d    # bit2 = 0: PTP card present
dmesg | grep -iE '8a340|idtcm|rsmu'
ls /dev/rsmu0
```

Expected messages:

```
8a3400x-phc 8a3400x-phc.0.auto: 4.8.8, Id: 0x4004  HW Rev: 5  OTP Config Select: 0
8a3400x-phc 8a3400x-phc.0.auto: loading firmware failed with -2     <- expected, no idtcm.bin
rsmu-cdev 8a3400x-cdev.1.auto: Probe rsmu0 successful
8a3400x-phc 8a3400x-phc.0.auto: PLL2 registered as ptp6
```

The PTP daughter card is optional. Without the card, the probe of `10-0058` fails
at boot and logs an error; this is expected and has no effect on the other devices.

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
| Downstream slave on C2-1 | SLAVE about 8 s after start; GM = upstream GM; offset rms 9.4 ns, max 40 ns; path delay about 380 ns |
| Downstream slave on X2 | SLAVE about 8 s after start; GM = upstream GM; offset rms 8.1 ns, max 24 ns; path delay about 255 ns |

The C port path delay is about 125 ns longer than the X port because of the 88X6141 PHY.

Upstream failure (X1 link down for 40 s):

| Event | ET3600 | Downstream slave |
|---|---|---|
| X1 link down | X1 FAULTY; ET3600 becomes grandmaster (own clock identity, clockClass 248) | Switches GM to the ET3600 within about 1 s; stays SLAVE; no time step |
| X1 link restored | X1 back to SLAVE after about 8 s | Switches GM back to the upstream GM; max offset below 100 ns during re-lock, below 30 ns after about 14 s |

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
| Downstream slave | SLAVE after about 7 s; GM = upstream GM; offset rms 2.9 ns, max 11 ns | GM = upstream GM; offset rms 3.0 ns, max 9 ns |
| Downstream path delay (sum of both links) | about 651 ns | about 527 ns |

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

Verified result: SLAVE about 8 s after start; offset rms 2.8 ns, |offset| max 13 ns; path delay 271 ns.

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
offset rms 3.0 ns, |offset| max 11 ns; path delay 387 ns. The extra ~116 ns compared with the X port is
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

BMCA makes one port SLAVE and keeps the other one LISTENING (standby). Both ports see
the same GM, so the choice depends on the GM port identity; in the test C1-1 was active.

| Event | Active port (C1-1) | Standby port (X1) |
|---|---|---|
| Both links up | SLAVE | LISTENING |
| Active link down | FAULTY | SLAVE within 1 s; no time step (max 14 ns) |
| Active link restored | SLAVE again within about 10 s (revertive) | LISTENING; offset up to 588 ns during the re-lock, below 10 ns about 15 s after the link came back |
| Standby link down / up | stays SLAVE, not affected | FAULTY, then LISTENING |

The test runs had no faults or timeouts outside the link-down events (rms mean 3.0 ns,
|offset| max 13 ns).

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

Verified result (C1-1 upstream, C2-1 downstream): the downstream slave locks
within about 4 s after the downstream instance starts (offset rms 4.9 ns, max 14 ns,
path delay 380 ns); the upstream instance stays locked (rms mean 2.9 ns, max 13 ns).
The downstream slave sees the ET3600 as its grandmaster (clockClass 6), not the
upstream GM.

Limitations — prefer section 4 when one profile can be used end to end:

- The downstream instance announces the ET3600 itself as grandmaster with a fixed
  `clockClass 6`. The upstream GM identity, its clockClass and `stepsRemoved` are
  not passed downstream.
- If the upstream is lost, the downstream instance keeps announcing `clockClass 6`.

---

## 7. SyncE (10G, C ports and X ports)

SyncE recovers the line frequency from an upstream port and makes the PTP card
(8A34004) generate the SerDes / PHY 156.25 MHz reference from it.

Supported upstream ports at 10G: C1-1 and C2-1 (section 7.3), X1 and X2 (section 7.4).
A C port and an X port can be configured together as redundant sources (section 7.5).

### 7.1 Clock path

```
C port:  upstream ──► 88X6141 (C1) RCLK B ─┐ CLK_OUT_SE1
                      88X6141 (C2) RCLK B ─┴─► 2:1 switch (CPLD 0x2C bit1) ─► 8A34004 CLK0  = IN0
X port:  upstream ──► CN103 GSERM (X1 / X2) recovered clock ─► GPIO39 ─────► 8A34004 nCLK0 = IN8
                                                                                              │
              DPLL5 (SyncE DPLL, selects IN0 / IN8) ──combo bus──► DPLL6 (DCO) ──► Q10 156.25 MHz
                                                                                              │
              Clock buffer (CPLD 0x2C bit0) ──► CN103 SerDes + both 88X6141 reference ◄───────┘
```

CLK0 and nCLK0 are two separate inputs only when INPUT_0 is single-ended; both the
C port and the X port setups use this mode.

| Item | C port | X port |
|---|---|---|
| Recovered clock source | 88X6141 line side, lane 0 | CN103 GSERM RX lane 0 (X1 = GSERM1, X2 = GSERM0) |
| Divider | 644.53125 MHz ÷ 16 | 257.8125 MHz ÷ 4 (BTSCLK) ÷ 2 (GPIO_CLK_SYNCE) |
| 8A34004 input | IN0 (CLK0), single-ended, 40.283203125 MHz | IN8 (nCLK0), single-ended, 32.2265625 MHz |
| DPLL5 reference priority | 0 | 1 |

| Item | Value |
|---|---|
| SyncE DPLL | DPLL5 (automatic reference selection, non-revertive; FOD 500 MHz → Q8 1PPS, Q9 25 MHz) |
| SerDes reference | Q10 = DPLL6 FOD 625 MHz ÷ 4 = 156.25 MHz (Q11 = 25 MHz) |
| PTP PHC (`IDT CM TOD2`) | DPLL2, write-frequency DCO, no output pin |

The 8A34004 has three channels (DPLL2, DPLL5, DPLL6), two input stages (CLK0/nCLK0,
CLK1/nCLK1) and four outputs (Q8–Q11). There is no 125 MHz output in the current OTP.

### 7.2 Differences from the OTP and the CPLD manual

| Item | Document / OTP | Actual (measured) | Action |
|---|---|---|---|
| CPLD `0x2C` bit1 | 1 = first 6141 = C1 | **0 = C1** (6141 at `eth=2 lmac=2`), 1 = C2 (`eth=2 lmac=0`) | Use bit1 = 0 for C1 |
| 8A34004 IN0 mode | Differential (`IN_MODE` 0x21) | Switch output is single-ended on CLK0; X port clock is on nCLK0 | Set `IN_MODE` = 0x01 |
| 8A34004 IN8 | Disabled | X port recovered clock (32.2265625 MHz) | Configure and enable IN8 (7.4 step 3) |
| 8A34004 IN1 | 32.2265625 MHz | CLK1 carries SMB_10M_IN | Not used |
| DPLL5 priority 1 | CLK8, disabled | Needed for the X port | Enable (7.4 step 4) |
| 6141 RCLK mux / divider | Not configured by the SDK (divider off) | Must be configured | Write F426 / F422 (7.3 step 1) |
| DPLL6 combo source | Primary = system DPLL (XO) | Must follow DPLL5 | Set primary = DPLL5 (7.3 step 4) |
| Hardware table "125M SyncE" | 125 MHz | 125 MHz needs a 1G link; at 10G the CN103 output is a divided 257.8125 MHz | Use 32.2265625 MHz |

### 7.3 Configuration (C1-1 or C2-1 at 10G)

Use the column that matches the upstream C port:

| Item | C1 upstream | C2 upstream |
|---|---|---|
| 6141 selection (`phy_diag`) | `echo "2 2" > $D/phy` | `echo "2 0" > $D/phy` |
| CPLD `0x2C`, SerDes on XO (step 2) | `0x01` | `0x03` |
| CPLD `0x2C`, SerDes on PTP card (step 6) | `0x00` | `0x02` |

The commands below show C1; for C2 replace the three values above.

All settings are runtime only and are lost on reboot. Run them in this order after the
port is up and the 8A34004 driver is loaded (section 2.3). Helper scripts are in `scripts/`.

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

### 7.4 Configuration (X1 or X2 at 10G)

| Item | X1 upstream | X2 upstream |
|---|---|---|
| `GPIO_CLK_SYNCEX(0)` (step 1) | `0x104` (GSERM1, lane 0, /2) | `0x004` (GSERM0, lane 0, /2) |
| `GSERMX_LANEX_BTSCLK_CFG` index (step 1 check) | `-a 1 -b 0` | `-a 0 -b 0` |

The commands below show X1. All settings are runtime only. CN103 registers are
accessed with `txcsr`.

```sh
# 1. CN103: recovered clock of X1 to GPIO39, 257.8125 MHz / 4 / 2 = 32.2265625 MHz
txcsr -x GSERMX_LANEX_BTSCLK_CFG -a 1 -b 0   # check: EN = 1, MIO_EN = 1, MIO_DRATIO = 2 (/4)
txcsr GPIO_CLK_SYNCEX -a 0 0x104             # QLM_SEL = 1 (X1), DIV = 1 (/2), LANE_SEL = 0
txcsr -x GPIO_BIT_CFGX -a 39                 # check: PIN_SEL = 3 (GPIO_CLK_SYNCE0)

# 2. 8A34004 IN0 single-ended: nCLK0 becomes the separate input IN8
python3 -I rsmu_write.py 0x2010c1bd -w 01

# 3. IN8: 32.2265625 MHz, enabled; LOS monitor on REF_MON_8 (the last byte re-applies the module)
python3 -I rsmu_write.py 0x2010c250 -w 40 81 de f5 00 00 80 00 01 00
python3 -I rsmu_write.py 0x2010c25d -w 01
python3 -I rsmu_write.py 0x2010c353 -w 03

# 4. DPLL5 reference priority 1 = CLK8, enabled; re-apply DPLL5 (DPLL_MODE, value unchanged)
python3 -I rsmu_write.py 0x2010c510 -w 11
python3 -I rsmu_write.py 0x2010c537 -w 00

# 5. DPLL6 follows DPLL5 (same as 7.3 step 4)
python3 -I rsmu_write.py 0x2010c56a -w 25
python3 -I rsmu_write.py 0x2010c56f -w 08

# 6. Wait for DPLL5 LOCKED on CLK8 (normally about 20 s)
python3 -I rsmu_write.py 0x2010c04c          # IN8 status: bit0 = 0 means signal present
python3 -I rsmu_write.py 0x2010c063          # DPLL5 current reference: 08 = CLK8
python3 -I synce_state.py check_locked && echo LOCKED

# 7. Only when DPLL5 is LOCKED: SerDes / PHY reference from the PTP card (bit0 = 0)
i2cset -y 4 0x40 0x2c 0x02
```

The CPLD rule of section 7.3 applies. CPLD `0x2C` bit1 only selects the C port
recovered clock and does not affect the X port.

### 7.5 C port and X port together

Configure the C port (7.3 steps 1–4) and the X port (7.4 steps 1–5). DPLL5 then has
two references:

| Priority | Reference | Source |
|---|---|---|
| 0 | CLK0 (IN0) | C port |
| 1 | CLK8 (IN8) | X port |

Reference switching is non-revertive: DPLL5 stays on the current reference while it is
valid, and changes only when that reference is lost. Set CPLD `0x2C` to `0x00` (C1)
or `0x02` (C2) once DPLL5 is LOCKED.

Verified behavior (C1-1 + X1, SerDes reference on the PTP card, PTP BC running):

| Event | DPLL5 | Links | PTP |
|---|---|---|---|
| Both sources valid | Stays on the current reference | Up | — |
| X port source lost while on CLK8 | Switches to CLK0 within 5 s, LOCKED after about 10 s | Stay up | No change |
| C port source lost while on CLK0 | Switches to CLK8 within 5 s, LOCKED after about 10 s | Stay up | No change |
| Lost source restored | Input valid again; DPLL5 stays on the current reference | Stay up | No change |

### 7.6 Verification

```sh
python3 -I synce_state.py status; echo
# expected: IN0 sig +0.0xx ppm  DPLL5 LOCKED  DPLL6 OPEN_LOOP  SYS LOCKED   (C port)
python3 -I rsmu_write.py 0x2010c063          # DPLL5 reference: 00 = CLK0 (C port), 08 = CLK8 (X port)
python3 -I rsmu_write.py 0x2010c04c          # X port: IN8 bit0 = 0 (signal present)
python3 -I rsmu_cfg.py | grep -E 'DPLL5|DPLL6'
i2cget -y 4 0x40 0x2c          # bit0 = 0 when the SerDes reference is on the PTP card
```

- `IN0 ... ppm` is the frequency offset of the recovered clock measured by the 8A34004.
  `+8191` / `-8192` means out of range (wrong divider, wrong CPLD bit1, or IN0 still
  differential).
- DPLL6 always reports `OPEN_LOOP`; this is normal for a DCO channel that follows DPLL5
  over the combo bus.

Verified result (X1, 10G):

| Step | Result |
|---|---|
| IN8 frequency offset | +0.004 ppm |
| DPLL5 | Selects CLK8, LOCKED within about 20 s |
| `0x2C` = 0x02 (SerDes reference on the PTP card) | DPLL5 stays LOCKED; X1 / X2 / C1-1 stay up |
| PTP BC (section 4), X1 upstream, downstream slave on X2 | ET3600 offset rms 6.6 ns, max 23 ns; downstream slave rms 7.8 ns, max 27 ns; no fault |
| X2 as source (`GPIO_CLK_SYNCEX(0)` = 0x004) | IN8 follows the X2 peer's frequency; path verified with a free-running peer. After switching back, DPLL5 needed a re-acquire (section 9) |

Verified result (C1-1 and C2-1, 10G):

| Step | Result |
|---|---|
| IN0 frequency offset | +0.009 ppm |
| DPLL5 | LOCKED within 5 s |
| `0x2C` bit0 → 0 | DPLL5 briefly LOCKREC (about 10 s, the 6141 reference also changes), then LOCKED; X1 / X2 / C1-1 stay up, no packet loss on ping |
| Switch back to bit0 = 1 | Links stay up |
| C2-1 upstream (6141 `eth=2 lmac=0`, `0x2C` = 0x03 → 0x02) | IN0 +0.009 ppm, DPLL5 LOCKED; after bit0 = 0 DPLL5 stays LOCKED, X1 / X2 / C2-1 up, ping OK |
| PTP BC (section 4) with SerDes reference on the PTP card | Unchanged (CN103 PTP counter is not derived from the SerDes reference): ET3600 offset rms 6.7 ns, max 28 ns; downstream slave on C2-1 locks to the GM, offset rms 7.8 ns, max 32 ns |

### 7.7 Revert

```sh
i2cset -y 4 0x40 0x2c 0x03                     # SerDes reference back to XO, CPLD default
python3 -I rsmu_write.py 0x2010c56a -w 28      # DPLL6 combo primary back to system DPLL
python3 -I rsmu_write.py 0x2010c56f -w 08
# X port (7.4)
python3 -I rsmu_write.py 0x2010c510 -w 10      # DPLL5 priority 1 = CLK8, disabled (OTP)
python3 -I rsmu_write.py 0x2010c537 -w 00
python3 -I rsmu_write.py 0x2010c353 -w 00      # REF_MON_8 off
python3 -I rsmu_write.py 0x2010c250 -w 40 86 58 cd 04 00 00 02 01 00
python3 -I rsmu_write.py 0x2010c25d -w a0      # IN8 disabled (OTP)
txcsr GPIO_CLK_SYNCEX -a 0 0x0
# C port (7.3) and IN0
python3 -I rsmu_write.py 0x2010c1bd -w 21      # IN0 back to OTP value (differential)
echo "2 2" > $D/phy
echo "c45 31 f422 0000" > $D/write_reg
echo "c45 31 f426 0000" > $D/write_reg
```

The CPLD returns to `0x03` on reboot. The 8A34004 settings were still present after
a system reboot in the tests, so use the commands above to return it to the OTP values.

### 7.8 Useful 8A34004 addresses (FW 4.8)

| Register | Address |
|---|---|
| STATUS (IN mon status +0x08 + n, DPLL status +0x18, DPLL5 reference +0x27, IN FFO +0x8C + 2n) | 0x2010c03c |
| INPUT_0.IN_MODE | 0x2010c1bd |
| INPUT_1.IN_MODE | 0x2010c1cd |
| INPUT_8 (frequency +0x00, IN_MODE +0x0D) | 0x2010c250 |
| REF_MON_8 (IN_MON_CFG +0x0B) | 0x2010c348 |
| DPLL_5 (REF_PRIORITY_0 +0x0F, REF_PRIORITY_1 +0x10, REF_MODE +0x35, DPLL_MODE +0x37) | 0x2010c500 |
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
| Probe error for `10-0058` at boot, no `/dev/rsmu0` | PTP daughter card not installed (CPLD `0x0d` bit2 = 1) | Expected on a system without the card. With the card installed, check the card seating and `i2cdetect -y 10`. |
| SyncE: IN0 offset reads `+8191` / `-8192` ppm, DPLL5 stays LOCKACQ | IN0 still differential, wrong CPLD `0x2C` bit1, or 6141 RCLK divider not set | Section 7.3 steps 1–3; bit1 = 0 for C1 |
| SyncE: IN0 LOS | The selected 6141 has no RCLK output (divider off) or CPLD bit1 selects the other PHY | Configure F426/F422 on the PHY selected by bit1 |
| SyncE (X port): IN8 LOS | IN0 still differential (nCLK0 is then not a separate input), or `GPIO_CLK_SYNCEX(0)` not set | Section 7.4 steps 1–3 |
| SyncE (X port): IN8 offset `+8191` / `-8192` ppm | IN8 frequency or `GPIO_CLK_SYNCEX(0)` divider does not match (32.2265625 MHz expected) | Section 7.4 steps 1 and 3 |
| SyncE: DPLL5 stays in LOCKREC for minutes although the input offset is small | The reference frequency jumped by tens of ppm before (for example the source was changed to a free-running peer and back) | Disable and re-enable the priority entry of the reference, e.g. for CLK8: `rsmu_write.py 0x2010c510 -w 10`, `0x2010c537 -w 00`, then `0x2010c510 -w 11`, `0x2010c537 -w 00` |
| SyncE (X port): DPLL5 stays on CLK0 or in HOLDOVER | DPLL5 priority 1 (CLK8) not enabled, or the current reference is still valid (non-revertive) | Section 7.4 step 4; section 7.5 |
| SyncE: DPLL5 does not lock although IN0 has a signal | The upstream partner's frequency is far off (for example a device without SyncE, tens of ppm), outside the SyncE pull-in range | Use a SyncE-capable upstream device. |
| All SerDes links drop after `0x2C` bit0 = 0 | PTP card output not valid (DPLL5 not locked / card not configured) | `i2cset -y 4 0x40 0x2c 0x01`; switch only when DPLL5 is LOCKED |

---

## 10. Test report

This section summarizes the hardware tests behind this guide.

### 10.1 Test setup

| Item | Value |
|---|---|
| DUT | ET3600, kernel 6.6.46, linuxptp 3.1.1, PTP daughter card (8A34004) installed |
| Port mode | C1 and C2 in breakout mode; C1-1, C2-1, X1, X2 at 10G |
| Grandmaster | Default 1588, L2, domain 0 on X1. G.8275.2, UDPv4, domain 2 on C1-1 (also the SyncE source) |
| GM time quality | GNSS not locked, clockClass 248 (free-running time). This is a property of the test setup |
| Downstream slave | 10G, hardware timestamping, `ptp4l -2 -s` |
| Downstream ports | C2-1 and X2, 10G (one at a time) |
| Sync rate | 1/s for the default 1588 profile, 16/s for G.8275.2 |
| Test duration | At least 15 min per test; statistics skip the first 60 s. Items marked "short test" are functional checks of a few minutes |

Offset values are the ptp4l servo residual (`master offset`). They show lock quality,
not absolute time error; no 1PPS measurement equipment was used. For G.8275.2 (16 Sync/s)
ptp4l prints one summary per second; "rms" is the mean of these summaries and "max" the
largest value. No long-term (multi-hour) run was made.

### 10.2 ET3600 locked to the grandmaster

| Scenario | Section | Offset rms | \|Offset\| max | Path delay |
|---|---|---|---|---|
| G.8275.2, X1 upstream | 6.1 | 2.8 ns | 13 ns | 271 ns |
| G.8275.2, C1-1 upstream | 6.2 | 3.0 ns | 11 ns | 387 ns |
| G.8275.2, X1 + C1-1 redundant (C1-1 active) | 6.3 | 3.0 ns | 13 ns | 387 ns |
| Default 1588, single-instance BC, X1 upstream | 4 | 6.7–7.2 ns | 27 ns | 272 ns |

All ports reached SLAVE within about 8 s after start. No FAULT or timeout in any run
except the intended link-down events.

Redundant upstream switchover (G.8275.2, X1 + C1-1). BMCA selects one port; with the same
GM on both ports the choice depends on the GM port numbers (C1-1 in this test).

| Event | Result |
|---|---|
| Active upstream (C1-1) down for 40 s | X1 SLAVE within 1 s, no time step (max 14 ns, rms 4.2 ns) |
| Active upstream restored | Back to C1-1 within about 10 s; offset up to 588 ns during the re-lock, below 10 ns about 15 s after the link came back |
| Standby upstream (X1) down / up | No effect on the active port (max 13 ns) |

### 10.3 Downstream results

| Test | Downstream C2-1 | Downstream X2 |
|---|---|---|
| BC (section 4): GM identity passed down, stepsRemoved 2 | rms 9.4 ns, max 40 ns; path delay 380 ns | rms 8.1 ns, max 24 ns; path delay 255 ns |
| BC, X1 down for 40 s | GM → ET3600 within ~1 s, stays SLAVE, max 19 ns | GM → ET3600 within ~1 s, stays SLAVE, max 16 ns |
| BC, X1 restored | GM → upstream GM; max 94 ns during re-lock, below 30 ns after ~14 s | GM → upstream GM; max 85 ns during re-lock, below 30 ns after ~14 s |
| E2E TC (section 5): parent = GM, stepsRemoved 1 | rms 2.9 ns, max 11 ns; path delay 651 ns (both links) | rms 3.0 ns, max 9 ns; path delay 527 ns (both links) |
| BC with SyncE active (SerDes reference on the PTP card) | C1 SyncE: rms 7.8 ns, max 32 ns | X1 SyncE: rms 7.8 ns, max 27 ns |
| BC during SyncE source switching (C1 ↔ X1) | not tested | rms 8.7 ns, max 25 ns |
| Two-instance BC (section 6.4): G.8275.2 upstream C1-1, 1588 downstream | rms 4.9 ns, max 14 ns; path delay 380 ns; upstream instance rms 2.9 ns, max 13 ns | not tested |

ET3600 (BC upstream port X1) in the same runs: rms 6.6–7.2 ns, max 21–28 ns; during
the X1 re-lock up to 136 ns, below 30 ns after about 11 s.

When the SerDes reference is switched to the PTP card (`0x2C` bit0 → 0) during
traffic, C1-1 and C2-1 went down for about 2 s and recovered; the downstream slave
stayed locked.

### 10.4 SyncE results

SyncE status was sampled every 10 s during the test runs.

| Test | Result |
|---|---|
| C1-1 upstream, 10G | IN0 +0.002 to +0.003 ppm, DPLL5 LOCKED on CLK0 for the whole run |
| C2-1 upstream, 10G | IN0 +0.009 ppm, DPLL5 LOCKED; links stay up after `0x2C` = 0x02 (short test) |
| X1 upstream, 10G | IN8 +0.002 to +0.004 ppm, DPLL5 LOCKED on CLK8 for the whole run |
| X2 upstream path | IN8 follows the X2 peer's frequency (short test) |
| SerDes reference on the PTP card | X1 / X2 / C1-1 / C2-1 stay up; C ports down for about 2 s at the switch |
| C1-1 + X1 redundant | X1 lost: DPLL5 on CLK0 at the next sample (≤ 10 s), stays LOCKED; X1 back: stays on CLK0 (non-revertive). C1 lost: DPLL5 on CLK8 at the next sample, LOCKREC for one sample, then LOCKED. Links and PTP unchanged |
| PTP BC with SyncE active | PTP results unchanged (CN103 PTP counter does not use the SerDes reference) |

### 10.5 Path delay and port latency

| Item | Value |
|---|---|
| X port link | about 255–272 ns |
| C port link | about 380–387 ns |
| C port minus X port | about 115–125 ns (fixed latency of the 88X6141 PHY) |
| TC residence time | microseconds (linuxptp TC forwards in software) |

PTP measures and compensates the path delay. Time error comes from the transmit /
receive asymmetry (error = asymmetry / 2), which the ptp4l offset does not show.

### 10.6 Open items

| Item | Status |
|---|---|
| 8A34004 OTP | Does not match the board for the X port (IN0 differential, IN8 disabled, DPLL5 priority 1 disabled); the runtime settings of section 7.4 are needed until the OTP is updated |
| Absolute time error and C port asymmetry | Not measured (needs 1PPS equipment) |
| SyncE at 25G, ET3600 as SyncE source for downstream | Out of scope |

---

## 11. Files

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
