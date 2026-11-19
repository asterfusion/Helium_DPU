# ET2500 CPLD I2C User Manual

> **Applicable board: ET2500.** Applicable PCB version: `CN102_A_V1.0`.

- Source revision: V1.2, September 25, 2024, Jaylon.
- CPLD I2C slave address: `0x40` (7-bit).
- CPLD I2C online upgrade address: `0x40` (7-bit).
- `RO`: read-only; `RW`: read/write; `Unused`: unused bits; `—`: default value not specified in the source.

## 1. Introduction

This document describes how to access the ET2500 CPLD through the Linux I2C interface. It covers I2C bus identification, mux channel selection, CPLD register reads, and the complete register map.

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

To dump the raw CPLD register values, run:

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

## 6. Troubleshooting

- **The expected mux channel is not listed:** Check that the I2C controller and mux drivers are loaded and inspect the system log for driver errors.
- **Address `0x40` is not detected:** Verify that the correct mux channel and bus number were selected. Also check the board power state.
- **The address is displayed as `UU`:** A kernel driver has claimed the address. Avoid direct access unless forced access has been approved for the current maintenance procedure.
- **A peripheral does not recover after reset:** Confirm that the reset bit was released to `1` and that the low pulse lasted more than 100 ms. Then check the peripheral power and driver status.

## Register Definitions

### 0x00 — CPLD Firmware Version

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | Firmware Version | CPLD firmware version. | RO | — |

### 0x01 — Board Hardware and BOM Versions

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7 | Unused | Unused. | - | 0 |
| 6:4 | bom_id | BOM version. | RO | — |
| 3 | Unused | Unused. | - | 0 |
| 2:0 | pcb_id | Board hardware version. | RO | — |

### 0x02 — Test Register

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | Test Register | Read/write verification register. Reads return the bitwise complement of the written value. For example, writing 0x5A returns 0xA5. | RW | 0xA5 |

### 0x03 — SFP+ Transmitter Fault

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:4 | Unused | Unused. | - | 0x0 |
| 3 | sfp_txfault3 | Optical port 4 transmitter fault. 0: normal; 1: optical module transmitter fault. | RO | — |
| 2 | sfp_txfault2 | Optical port 3 transmitter fault. 0: normal; 1: optical module transmitter fault. | RO | — |
| 1 | sfp_txfault1 | Optical port 2 transmitter fault. 0: normal; 1: optical module transmitter fault. | RO | — |
| 0 | sfp_txfault0 | Optical port 1 transmitter fault. 0: normal; 1: optical module transmitter fault. | RO | — |

### 0x04 — SFP+ Module Absent

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:4 | Unused | Unused. | - | 0x0 |
| 3 | sfp_m_abs3_n | Optical port 4 module presence. 0: module present; 1: module absent. | RO | — |
| 2 | sfp_m_abs2_n | Optical port 3 module presence. 0: module present; 1: module absent. | RO | — |
| 1 | sfp_m_abs1_n | Optical port 2 module presence. 0: module present; 1: module absent. | RO | — |
| 0 | sfp_m_abs0_n | Optical port 1 module presence. 0: module present; 1: module absent. | RO | — |

### 0x05 — SFP+ Loss of Signal

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:4 | Unused | Unused. | - | 0x0 |
| 3 | sfp_los3 | Optical port 4 loss of signal. 0: normal; 1: receiver loss of signal. | RO | — |
| 2 | sfp_los2 | Optical port 3 loss of signal. 0: normal; 1: receiver loss of signal. | RO | — |
| 1 | sfp_los1 | Optical port 2 loss of signal. 0: normal; 1: receiver loss of signal. | RO | — |
| 0 | sfp_los0 | Optical port 1 loss of signal. 0: normal; 1: receiver loss of signal. | RO | — |

### 0x06 — SFP+ Transmitter Disable

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:4 | Unused | Unused. | - | 0x0 |
| 3 | sfp_tx_dis_ctl3 | Optical port 4 transmitter control. 0: enable the optical module transmitter; 1: disable the transmitter. | RW | 0x0 |
| 2 | sfp_tx_dis_ctl2 | Optical port 3 transmitter control. 0: enable the optical module transmitter; 1: disable the transmitter. | RW | 0x0 |
| 1 | sfp_tx_dis_ctl1 | Optical port 2 transmitter control. 0: enable the optical module transmitter; 1: disable the transmitter. | RW | 0x0 |
| 0 | sfp_tx_dis_ctl0 | Optical port 1 transmitter control. 0: enable the optical module transmitter; 1: disable the transmitter. | RW | 0x0 |

### 0x07 — Board Power Status 1

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7 | vcc5v_pg | VCC5V power status. 1: power good; 0: power not properly established. | RO | — |
| 6 | vdd_ddr_1v1_pg | CN102 VDD_DDR power status. 1: power good; 0: power not properly established. | RO | — |
| 5 | vcc1v8_pg | CN102 VDD_IO power status. 1: power good; 0: power not properly established. | RO | — |
| 4 | vdd_1v2_pg | CN102 VDD_HA power status. 1: power good; 0: power not properly established. | RO | — |
| 3 | vdd_dig_0v75_pg | CN102 VDD_DIG power status. 1: power good; 0: power not properly established. | RO | — |
| 2 | vdd_sys_pg | CN102 VDD_SYS power status. 1: power good; 0: power not properly established. | RO | — |
| 1 | vdd_core_pg | CN102 VDD_CORE power status. 1: power good; 0: power not properly established. | RO | — |
| 0 | W_power_good_all | Status of all onboard power supplies. 1: all supplies powered up normally; 0: one or more supplies did not power up normally. | RO | — |

### 0x08 — Board Power Status 2

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7 | Unused | Unused. | - | 0 |
| 6 | dimm_pwr_good | DDR5 DIMM power status. 1: power good; 0: power not properly established. | RO | — |
| 5 | phy1_avddh_1v8_pg | 88E2540 AVDDH power status. 1: power good; 0: power not properly established. | RO | — |
| 4 | phy1_avdd_1v2_pg | 88E2540 AVDD power status. 1: power good; 0: power not properly established. | RO | — |
| 3 | phy1_dvdd_0v8_pg | 88E2540 DVDD power status. 1: power good; 0: power not properly established. | RO | — |
| 2 | vcc1v05_pg | VCC1V05 power status. 1: power good; 0: power not properly established. | RO | — |
| 1 | vcc1v5_pg | VCC1V5 power status. 1: power good; 0: power not properly established. | RO | — |
| 0 | vcc3v3_pg | VCC3V3 power status. 1: power good; 0: power not properly established. | RO | — |

### 0x09 — Reset Control

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7 | W_5g_rst_ctl | 5G module reset control. 1: normal operation; 0: assert reset. | RW | 0x1 |
| 6 | W_ptn2_rst_ctl | PTN3222GM-2 reset control. 1: normal operation; 0: assert reset. | RW | 0x1 |
| 5 | W_ptn1_rst_ctl | PTN3222GM-1 reset control. 1: normal operation; 0: assert reset. | RW | 0x1 |
| 4 | W_sfp_pca_rst_ctl | PCA9548 for the optical ports reset control. 1: normal operation; 0: assert reset. | RW | 0x1 |
| 3 | W_1781_rst_ctl | 88E1781 reset control. 1: normal operation; 0: assert reset. | RW | 0x1 |
| 2 | W_2540_rst_ctl | 88E2540 reset control. 1: normal operation; 0: assert reset. | RW | 0x1 |
| 1 | W_usb_sata_rst_ctl | USB-to-SATA bridge reset control. 1: normal operation; 0: assert reset. | RW | 0x1 |
| 0 | W_usb_hub_rst_ctl | USB hub reset control. 1: normal operation; 0: assert reset. | RW | 0x1 |

To reset a device, write 0 followed by 1. The interval from reset assertion to release must be greater than 100 ms.

### 0x0A — CPU Boot Status

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:1 | Unused | Unused. | - | 0x0 |
| 0 | cpu_boot_success | CPU boot status. 0: booting or boot unsuccessful; 1: boot successful.<br>This bit controls the front panel SYS LED: 0 makes the green LED blink at 2 Hz; 1 keeps the green LED on. Set this bit to 1 after the CPU boots successfully. It resets automatically when the CPU restarts. | RW | 0x0 |

### 0x0B — Configuration 1

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:3 | Unused | Unused. | - | 0x0 |
| 2 | W_eeprom_wp_ctl | Write protection for the onboard EEPROM (D14, stores FRU information). 0: disabled; 1: enabled. | RW | 0x0 |
| 1 | W_over_temp_en_ctl | Overtemperature protection. 0: disabled; 1: enabled.<br>When enabled, reaching the configured chip temperature threshold triggers a board reset. Before enabling protection, configure the overtemperature threshold of the CN102 internal temperature sensor; 100°C is recommended. | RW | 0x0 |
| 0 | W_wd_enable_ctl | CN102 watchdog enable. 0: disabled; 1: enabled.<br>CN102 GPIO45 supplies the watchdog feed signal. Before enabling the watchdog, configure GPIO45 to output a square wave with a period of 1 second to prevent an unintended watchdog reset. | RW | 0x0 |

### 0x0C — 5G and Wi-Fi Module Configuration

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:6 | Unused | Unused. | - | 0x0 |
| 5 | w_5g_dpr_ctl | 5G module power configuration. 1: maximum RF transmit power is not reduced; 0: maximum module transmit power is reduced after executing AT+QSAR. | RW | 1 |
| 4 | W_bt_disable_ctl | Bluetooth control. 1: enabled; 0: disabled. | RW | 1 |
| 3 | W_wifi_disable_ctl | Wi-Fi module control. 1: enabled; 0: disabled. | RW | 1 |
| 2 | W_5g_gnss_disable_ctl | 5G module GNSS control. 1: enabled; 0: disabled. | RW | 1 |
| 1 | W_5g_airplane_mode_ctl | 5G module airplane mode control. 1: normal operation; 0: airplane mode. | RW | 1 |
| 0 | W_5g_on_ctl | 5G module power control. 1: power on; 0: power off. | RW | 1 |

### 0x0D — SIM Card Presence

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:2 | Unused | Unused. | - | 0x0 |
| 1 | usim2_pres_n | SIM2 presence status. 0: absent; 1: present. | RO | — |
| 0 | usim1_pres_n | SIM1 presence status. 0: absent; 1: present. | RO | — |

### 0x0E — Fan 1 Speed

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | Fan1_speed | Fan revolutions per second. Multiply by 60 to obtain revolutions per minute (RPM). | RO | — |

### 0x0F — Fan 2 Speed

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | Fan2_speed | Fan revolutions per second. Multiply by 60 to obtain revolutions per minute (RPM). | RO | — |

### 0x10 — Fan Status

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:2 | Unused | Unused. | - | 0x0 |
| 1 | Fan2_fail | Fan module 2 failure indication. A stopped fan is considered failed. 0: normal; 1: failed. | RO | — |
| 0 | Fan1_fail | Fan module 1 failure indication. A stopped fan is considered failed. 0: normal; 1: failed. | RO | — |

### 0x11 — Manual Fan Speed Level Configuration

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:3 | Unused | Unused. | - | 0 |
| 2:0 | W_manual_fan_speed | Software configuration of the fan speed level, from 0 to 7. Level 0 is the lowest speed; level 7 is full speed. <br>The fan uses automatic speed control by default. For manual control, configure the speed level and set register 0x2C to 1. | RW | 3 |

### 0x12 — PoE Configuration

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:2 | Unused | Unused. | - | 0 |
| 1 | W_poe_disable_port_ctl | Quickly disable power to all PoE ports. 0: disable power to all PoE ports; 1: normal PoE operation. | RW | 1 |
| 0 | W_poe_reset_ctl | PoE reset control. 0: reset PoE peripherals; 1: normal operation.<br>To reset, write 0 followed by 1, with an interval greater than 100 ms. | RW | 1 |

### 0x13 — PoE Status

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:3 | Unused | Unused. | - | 0 |
| 2 | i2c_message_ready | I2C data readiness indication for the management CPU. 0: I2C ready; 1: I2C not ready.<br>This bit is not needed when UART communication is used. | RO | — |
| 1 | mcu_int | PoE interrupt output. 0: interrupt asserted; 1: no interrupt.<br>The events that generate interrupts can be configured. | RO | — |
| 0 | sys_ok | PoE management MCU status. 0: the MCU is operating normally and the input Vmain supply is within the required range; 1: abnormal. | RO | — |

### 0x14 — Front Panel LOC LED Control

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:1 | Unused | Unused. | - | 0 |
| 0 | W_loc_led_ctl | Locates the device among multiple devices. 0: front panel LOC LED off; 1: blue LOC LED blinks at 4 Hz. | RW | 0 |

### 0x15 — Multiphase Power Status

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:4 | Unused | Unused. | - | 0 |
| 3 | vddcore_oc_alert_n | Multiphase power OC_ALERT status. 0: LOOP2 overcurrent alarm; 1: normal. | RO | — |
| 2 | xdpe132g5_cat_flt | Multiphase power CAT_FLT status. 0: LOOP1 overcurrent alarm; 1: normal. | RO | — |
| 1 | xdpe_vrhot_n | Multiphase power HOT status. 0: overtemperature alarm; 1: normal. | RO | — |
| 0 | Unused | Unused. | - | 0 |

### 0x16 — Global Reset Control

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:1 | Unused | Unused. | - | 0 |
| 0 | W_payload_auto_reset | Quick reset of the entire board. 0: reset the board; 1: normal operation.<br>Write 0 to initiate a quick reset. This bit automatically returns to 1 after 100 ms; the CPU does not need to write 1. | RW | 1 |

### 0x17 — PHY Interrupt Status

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:2 | Unused | Unused. | - | 0 |
| 1 | Phy2_intn | PHY2 (88E1781) interrupt indication. 0: interrupt asserted; 1: normal. | RO | — |
| 0 | Phy1_intn | PHY1 (88E2540) interrupt indication. 0: interrupt asserted; 1: normal. | RO | — |

### 0x18 — LM75 Current Temperature

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_temp_lm75 | The CPU writes the current LM75 temperature. The CPLD uses the LM75 and TMP400 temperatures for automatic fan speed control.<br>Ambient temperature sensor path: I2C-1 → PCA9548A (0x70), channel 5 → LM75 (U51, 0x48).<br>Update every 5 seconds is recommended. Example: for 25°C, write decimal 25. | RW | 0 |

### 0x19 — CN102 Current Junction Temperature

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_temp_tmp400 | The CPU writes the current CN102 junction temperature measured by the onboard TMP400 sensor. The CPLD uses the LM75 and TMP400 temperatures for automatic fan speed control.<br>Junction temperature sensor path: I2C-1 → PCA9548A (0x70), channel 4 → TMP400 (D15, 0x18).<br>Update every 5 seconds is recommended. Example: for 70°C, write decimal 70. | RW | 0 |

### 0x1A — Automatic Fan Speed Threshold Update Enable

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:1 | Unused | Unused. | - | 0 |
| 0 | W_temperature_thresholds_load | 0: use the default thresholds built into the CPLD for automatic fan speed control.<br>1: use the thresholds configured in registers 0x1B–0x2A. | RW | 0 |

### 0x1B — Fan Level 1 to 2 LM75 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_1_2_lm75 | LM75 temperature threshold configured by the CPU for automatic fan speed control when changing from level 1 to level 2. Configuration is generally not required. | RW | 0 |

### 0x1C — Fan Level 1 to 2 TMP400 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_1_2_tmp400 | TMP400 temperature threshold configured by the CPU for automatic fan speed control when changing from level 1 to level 2. Configuration is generally not required. | RW | 0 |

### 0x1D — Fan Level 2 to 3 LM75 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_2_3_lm75 | LM75 temperature threshold configured by the CPU for automatic fan speed control when changing from level 2 to level 3. Configuration is generally not required. | RW | 0 |

### 0x1E — Fan Level 2 to 3 TMP400 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_2_3_tmp400 | TMP400 temperature threshold configured by the CPU for automatic fan speed control when changing from level 2 to level 3. Configuration is generally not required. | RW | 0 |

### 0x1F — Fan Level 3 to 5 LM75 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_3_5_lm75 | LM75 temperature threshold configured by the CPU for automatic fan speed control when changing from level 3 to level 5. Configuration is generally not required. | RW | 0 |

### 0x20 — Fan Level 3 to 5 TMP400 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_3_5_tmp400 | TMP400 temperature threshold configured by the CPU for automatic fan speed control when changing from level 3 to level 5. Configuration is generally not required. | RW | 0 |

### 0x21 — Fan Level 5 to 7 LM75 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_5_7_lm75 | LM75 temperature threshold configured by the CPU for automatic fan speed control when changing from level 5 to level 7. Configuration is generally not required. | RW | 0 |

### 0x22 — Fan Level 5 to 7 TMP400 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_5_7_tmp400 | TMP400 temperature threshold configured by the CPU for automatic fan speed control when changing from level 5 to level 7. Configuration is generally not required. | RW | 0 |

### 0x23 — Fan Level 7 to 5 LM75 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_7_5_lm75 | LM75 temperature threshold configured by the CPU for automatic fan speed control when changing from level 7 to level 5. Configuration is generally not required. | RW | 0 |

### 0x24 — Fan Level 7 to 5 TMP400 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_7_5_tmp400 | TMP400 temperature threshold configured by the CPU for automatic fan speed control when changing from level 7 to level 5. Configuration is generally not required. | RW | 0 |

### 0x25 — Fan Level 5 to 3 LM75 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_5_3_lm75 | LM75 temperature threshold configured by the CPU for automatic fan speed control when changing from level 5 to level 3. Configuration is generally not required. | RW | 0 |

### 0x26 — Fan Level 5 to 3 TMP400 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_5_3_tmp400 | TMP400 temperature threshold configured by the CPU for automatic fan speed control when changing from level 5 to level 3. Configuration is generally not required. | RW | 0 |

### 0x27 — Fan Level 3 to 2 LM75 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_3_2_lm75 | LM75 temperature threshold configured by the CPU for automatic fan speed control when changing from level 3 to level 2. Configuration is generally not required. | RW | 0 |

### 0x28 — Fan Level 3 to 2 TMP400 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_3_2_tmp400 | TMP400 temperature threshold configured by the CPU for automatic fan speed control when changing from level 3 to level 2. Configuration is generally not required. | RW | 0 |

### 0x29 — Fan Level 2 to 1 LM75 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_2_1_lm75 | LM75 temperature threshold configured by the CPU for automatic fan speed control when changing from level 2 to level 1. Configuration is generally not required. | RW | 0 |

### 0x2A — Fan Level 2 to 1 TMP400 Threshold

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:0 | W_2_1_tmp400 | TMP400 temperature threshold configured by the CPU for automatic fan speed control when changing from level 2 to level 1. Configuration is generally not required. | RW | 0 |

### 0x2B — Current Fan Speed Level

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:3 | Unused | Unused. | - | 0 |
| 2:0 | W_fan_speed_out | Current fan speed level. 0: lowest speed; 7: highest speed. | RO | — |

### 0x2C — Fan Speed Control Mode Configuration

| Bit | Name | Description | Type | Default |
| --- | --- | --- | --- | --- |
| 7:1 | Unused | Unused. | - | 0 |
| 0 | W_fan_mode_ctl | 0: automatic fan speed control; use with registers 0x18 and 0x19.<br>1: manual fan speed control; use with register 0x11. | RW | 0 |

## Revision History

| Version | Author / Editor | Date | Main Changes |
| --- | --- | --- | --- |
| V1.0 | Jaylon | 2024-07-16 | Initial draft. |
| V1.1 | Jaylon | 2024-08-26 | Completed register 0x15 and changed the register name for 0x17. |
| V1.2 | Jaylon | 2024-09-25 | Added registers 0x18–0x2C. |


©2024 Asterfusion.  All rights reserved.
