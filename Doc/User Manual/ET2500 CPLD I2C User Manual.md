# ET2500 CPLD I2C User Manual

## 1. Introduction

This document describes how to access the ET2500 CPLD through the Linux I2C interface. It covers I2C bus identification, CPLD register reads, and peripheral reset control.

> **Warning:** Writing an incorrect value to the CPLD may reset multiple devices or interrupt system operation. Read the current register value and modify only the required bit.

## 2. Prerequisites

- Log in to the ET2500 Linux system.
- Ensure that the `i2c-tools` package is installed.
- Use an account with `sudo` privileges.
- The CPLD uses the 7-bit I2C address `0x40`.

## 3. Identify the CPLD I2C Bus

List all registered I2C adapters:

```bash
i2cdetect -l
```

Find the adapter whose name contains `i2c-0-mux (chan_id 1)`. Note the Linux I2C bus number at the beginning of that line. For example, if the adapter is listed as `i2c-6`, use bus number `6` in the following commands.

The bus number may differ between software versions or systems. Always detect it instead of assuming that it is `6`.

### 3.1 I2C Mux Channel Selection

The I2C mux is connected to parent bus `i2c-0` at the 7-bit address `0x71`. The CPLD is connected through mux channel 1:

```text
i2c-0 -> I2C mux (0x71) -> channel 1 -> CPLD (0x40)
```

Select channel 1 by writing `0x02` to the I2C mux:

```bash
sudo i2cset -y -f 0 0x71 0x02
```

After selecting channel 1, find its child bus with `i2cdetect -l`.

For example, if `i2cdetect -l` shows the following entry:

```text
i2c-6   i2c   i2c-0-mux (chan_id 1)   I2C adapter
```

use bus number `6` directly:

```bash
sudo i2cget -y -f 6 0x40 0x00
```

Optionally, confirm that the CPLD is visible at address `0x40`:

```bash
sudo i2cdetect -y -r 6
```

## 4. Dump the CPLD Registers

To display the CPLD register map, run:

```bash
sudo i2cdump -y -f 6 0x40
```

In this example:

- `6` is the I2C bus number found in Section 3.
- `0x40` is the CPLD I2C address.
- `-y` disables the interactive confirmation prompt.
- `-f` forces access even if the bus or device is claimed by a kernel driver.

> **Caution:** Forced access can interfere with a kernel driver that is using the device. Use `-f` only when necessary and ensure that no other software is accessing the CPLD at the same time.

## 5. Identification Registers

| Address | Register | Description |
| --- | --- | --- |
| `0x00` | CPLD firmware version | Contains the CPLD firmware version number. |
| `0x01` | Board version | Bits `[6:4]` contain the BOM version (`bom_id`); bits `[2:0]` contain the PCB hardware version (`pcb_id`). Bits `7` and `3` are reserved. |

Read the CPLD firmware version:

```bash
sudo i2cget -y -f 6 0x40 0x00
```

Read the board version register:

```bash
sudo i2cget -y -f 6 0x40 0x01
```

If the value read from register `0x01` is stored in `VALUE`, the two fields can be decoded as follows:

```text
bom_id = (VALUE >> 4) & 0x07
pcb_id = VALUE & 0x07
```

For example, a register value of `0x52` indicates `bom_id = 5` and `pcb_id = 2`.

## 6. Reset Control Register

Register `0x09` controls resets for the ET2500 peripherals. All reset signals are active low:

- Write `0` to assert reset.
- Write `1` to release reset and allow normal operation.

| Bit | Name | Controlled device | `0` | `1` | Access | Default |
| ---: | --- | --- | --- | --- | --- | ---: |
| 7 | `W_5g_rst_ctl` | 5G module | Reset asserted | Normal operation | RW | `1` |

### 6.1 Reset Procedure

To reset a peripheral, clear its control bit, wait for at least 100 ms, and then set the bit again. Because register `0x09` controls several devices, use a read-modify-write sequence so that all unrelated bits retain their current values.

The following example resets the 5G module (bit 7). The `-m 0x80` option changes only bit 7 and preserves all other bits:

```bash
sudo i2cset -y -f -m 0x80 6 0x40 0x09 0x00
sleep 0.1
sudo i2cset -y -f -m 0x80 6 0x40 0x09 0x80
```

> **Important:** The interval between asserting and releasing reset must be at least 100 ms. Do not modify the unused bit or any unrelated reset-control bit.

### 6.2 Verify the Result

Read register `0x09` after the reset operation:

```bash
sudo i2cget -y -f 6 0x40 0x09
```

Confirm that the target bit has returned to `1`. If it remains `0`, the corresponding peripheral is still held in reset.

## 7. 5G and Wi-Fi Module Configuration Register

Register `0x0C` contains the 5G and Wi-Fi module control fields. The currently defined field is the 5G module power control at bit 0.

| Bit | Name | Description | `0` | `1` | Access |
| ---: | --- | --- | --- | --- | --- |
| 7:1 | Reserved | Reserved; preserve the current values. | — | — | — |
| 0 | `W_5g_on_ctl` | Controls 5G module power. | Power off | Power on | RW |

Read the register:

```bash
sudo i2cget -y -f 6 0x40 0x0C
```

### 7.1 Power On the 5G Module

Set bit 0 while preserving all other bits:

```bash
sudo i2cset -y -f -m 0x01 6 0x40 0x0C 0x01
```

### 7.2 Power Off the 5G Module

Clear bit 0 while preserving all other bits:

```bash
sudo i2cset -y -f -m 0x01 6 0x40 0x0C 0x00
```

Read register `0x0C` again to verify the result. Bit 0 must be `1` when the 5G module is powered on and `0` when it is powered off.

> **Important:** Do not write a fixed full-byte value to register `0x0C`. Its other bits may control additional module functions; always use a read-modify-write sequence.

## 8. Troubleshooting

- **The expected mux channel is not listed:** Check that the I2C controller and mux drivers are loaded and inspect the system log for driver errors.
- **Address `0x40` is not detected:** Verify that the correct mux channel and bus number were selected. Also check the board power state.
- **The address is displayed as `UU`:** A kernel driver has claimed the address. Avoid direct access unless forced access has been approved for the current maintenance procedure.
- **A peripheral does not recover after reset:** Confirm that the reset bit was released to `1` and that the low pulse lasted at least 100 ms. Then check the peripheral power and driver status.
