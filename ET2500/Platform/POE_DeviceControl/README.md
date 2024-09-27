# POE Device Control

# 目录

[简介](#简介)

[功能](#功能)

[目录结构](#目录结构)

[构建和安装](#构建和安装)

[使用方法](#使用方法)

[系统架构](#系统架构)

[注意事项](#注意事项)

# 简介

POE Device Control 是一个用于管理 Power over Ethernet (POE) 设备的命令行工具。该工具支持多种操作，包括初始化设备、设置最大功率、优先级、遗留检测和 LED 状态。

# 功能

- `poe init` - 初始化 POE 设备。
- `poe show` - 显示当前设备状态。
- `poe enable|disable all|EthernetX` - 启用或禁用所有端口或指定的以太网端口。
- `maxpower {60w|30w|15w|30w-at} all|EthernetX` - 设置所有端口或指定端口的最大功率。
- `priority {low|high|critical} all|EthernetX` - 设置所有端口或指定端口的优先级。
- `legacydetect {enable|disable} all|EthernetX` - 启用或禁用遗留检测。
- `led on|off all|EthernetX` - 控制所有端口或指定端口的 LED 状态。

# 目录结构

```
.
|-- CMakeLists.txt          	# 构建配置文件
|-- ReadMe.md               	# 本文档
`-- src                     	# 源代码目录
    |-- BtWorkSpace.cc      	# BT 工作空间实现
    |-- BtWorkSpace.h       	# BT 工作空间头文件
    |-- ExecBase.cc         	# 执行基础命令实现
    |-- ExecBase.h          	# 执行基础命令头文件
    |-- LedCommand.cc       	# LED 控制命令实现
    |-- LedCommand.h        	# LED 控制命令头文件
    |-- LogMessage.cc       	# 日志信息处理实现
    |-- LogMessage.h        	# 日志信息处理头文件
    |-- PoeCommand.cc       	# POE 相关命令实现
    |-- PoeCommand.h        	# POE 相关命令头文件
    |-- StructFormatter.cc   	# 结构格式化实现
    |-- StructFormatter.h    	# 结构格式化头文件
    |-- UserInteraction.cc   	# 用户交互实现
    |-- UserInteraction.h    	# 用户交互头文件
    |-- Utils.cc            	# 工具函数实现
    |-- Utils.h             	# 工具函数头文件
    `-- main.cc             	# 程序入口
```

# 构建和安装

本模块采用C++20编写，确保您已安装 CMake 和编译器，然后，使用以下命令构建项目：

```bash
cd POE_DeviceControl
mkdir build
cd build
cmake ..
make
```

要安装该工具，请执行：

```bash
make install
```

# 使用方法

```bash
poe_device_control poe init
poe_device_control poe show 
poe_device_control poe enable|disable all|EthernetX
poe_device_control maxpower {60w|30w|15w|30w-at} all|EthernetX
poe_device_control priority {low|high|critical} all|EthernetX
poe_device_control legacydetect {enable|disable} all|EthernetX
poe_device_control led on|off all|EthernetX	
```

# 系统架构

系统采用模块化设计，包括以下核心模块：

- **Logger**: 负责记录操作日志和错误信息
- **UserInteraction**: 处理用户输入并提供反馈
- **LedCommand**: 控制 LED 状态
- **PoeCommand**: 处理 PoE 相关命令
- **BtWorkSpace**: 执行API BT

# 注意事项

1. **初始化**
   - 每次开机之后，都要执行一次初始化，即`poe_device_control poe init`
2. **开启和关闭**
   - 必须在设备总功率足够的情况下才能开启。
   - 必须在当前可用功率大于等于需求功率时才能开启，否则会导致 Port Status 1F (overload)。
3. **显示**
   - 开启和关闭以及切换设备状态有一定延迟，需要等待一段时间后再执行 `poe show`。
4. **功率限制**
   - 当设置30w-at时，2.5G 端口实际表现为 60w-at。