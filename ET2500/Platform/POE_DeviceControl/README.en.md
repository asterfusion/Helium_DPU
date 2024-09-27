# POE Device Control

## Contents

[Introduction](#introduction)

[Features](#features)

[Directory Structure](#directory-structure)

[Building and Installation](#building-and-installation)

[Usage](#usage)

[System Architecture](#system-architecture)

[Notes](#notes)

## Introduction

POE Device Control is a command-line tool for managing Power over Ethernet (POE) devices. This tool supports various operations, including initializing devices, setting maximum power, priority, legacy detection, and LED status.

## Features

- `poe init` - Initialize the POE device.
- `poe show` - Display the current device status.
- `poe enable|disable all|EthernetX` - Enable or disable all ports or a specified Ethernet port.
- `maxpower {60w|30w|15w|30w-at} all|EthernetX` - Set the maximum power for all ports or a specified port.
- `priority {low|high|critical} all|EthernetX` - Set the priority for all ports or a specified port.
- `legacydetect {enable|disable} all|EthernetX` - Enable or disable legacy detection.
- `led on|off all|EthernetX` - Control the LED status for all ports or a specified port.

## Directory Structure

```
.
|-- CMakeLists.txt           # Build configuration file
|-- ReadMe.md                # This document
`-- src                      # Source code directory
    |-- BtWorkSpace.cc       # BT workspace implementation
    |-- BtWorkSpace.h        # BT workspace header file
    |-- ExecBase.cc          # Base command execution implementation
    |-- ExecBase.h           # Base command execution header file
    |-- LedCommand.cc        # LED control command implementation
    |-- LedCommand.h         # LED control command header file
    |-- LogMessage.cc        # Log message handling implementation
    |-- LogMessage.h         # Log message handling header file
    |-- PoeCommand.cc        # POE-related command implementation
    |-- PoeCommand.h         # POE-related command header file
    |-- StructFormatter.cc    # Structure formatting implementation
    |-- StructFormatter.h     # Structure formatting header file
    |-- UserInteraction.cc    # User interaction implementation
    |-- UserInteraction.h     # User interaction header file
    |-- Utils.cc             # Utility functions implementation
    |-- Utils.h              # Utility functions header file
    `-- main.cc              # Program entry point
```

## Building and Installation

This module is written in C++20. Ensure you have CMake and a compiler installed. Then, use the following commands to build the project:

```bash
cd POE_DeviceControl
mkdir build
cd build
cmake ..
make
```

To install the tool, execute:

```bash
make install
```

## Usage

```bash
poe_device_control poe init
poe_device_control poe show 
poe_device_control poe enable|disable all|EthernetX
poe_device_control maxpower {60w|30w|15w|30w-at} all|EthernetX
poe_device_control priority {low|high|critical} all|EthernetX
poe_device_control legacydetect {enable|disable} all|EthernetX
poe_device_control led on|off all|EthernetX	
```

## System Architecture

The system adopts a modular design, including the following core modules:

- **Logger**: Responsible for recording operation logs and error messages.
- **UserInteraction**: Handles user input and provides feedback.
- **LedCommand**: Controls the LED status.
- **PoeCommand**: Processes POE-related commands.
- **BtWorkSpace**: Executes API BT.

## Notes

1. **Initialization**
   - After each startup, an initialization must be performed, which is `poe_deevice_comtrol poe init`
2. **Enabling and Disabling**
   - Devices can only be enabled if the total power is sufficient.
   - Devices must be enabled when the available power is greater than or equal to the required power; otherwise, it will result in Port Status 1F (overload).
3. **Display**
   - There is a certain delay when enabling, disabling, or switching device states; please wait for a while before executing `poe show`.
4. **Power Limitations**
   - When setting to 30w-at, the 2.5G port behaves as 60w-at.