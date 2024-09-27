#pragma once
#include <stdint.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_set>
#include "LogMessage.h"

typedef struct InputMessage {
    uint8_t send_00key;
    uint8_t send_01echo;
    uint8_t send_02sub;
    uint8_t send_03sub1;
    uint8_t send_04sub2;
    uint8_t send_05data;
    uint8_t send_06data;
    uint8_t send_07data;
    uint8_t send_08data;
    uint8_t send_09data;
    uint8_t send_10data;
    uint8_t send_11data;
    uint8_t send_12data;
} InputMessage;

typedef struct OutputMessage {
    uint8_t pmsgCode;

    uint8_t send_00key;
    uint8_t send_01echo;
    uint8_t send_02sub;
    uint8_t send_03sub1;
    uint8_t send_04sub2;
    uint8_t send_05data;
    uint8_t send_06data;
    uint8_t send_07data;
    uint8_t send_08data;
    uint8_t send_09data;
    uint8_t send_10data;
    uint8_t send_11data;
    uint8_t send_12data;

    uint8_t read_00key;
    uint8_t read_01echo;
    uint8_t read_02sub;
    uint8_t read_03sub1;
    uint8_t read_04sub2;
    uint8_t read_05data;
    uint8_t read_06data;
    uint8_t read_07data;
    uint8_t read_08data;
    uint8_t read_09data;
    uint8_t read_10data;
    uint8_t read_11data;
    uint8_t read_12data;
} OutputMessage;

extern const std::vector<std::pair<std::string, uint8_t>> Interfaces;

typedef struct PortCode {
    uint8_t interfaceAddr;
    uint8_t PortStatus = 0x1A;
    uint16_t Current = 0;
    uint16_t Voltage = 0;
    uint16_t Power = 0;
    uint8_t PortOperationMode = 0xFF;
    uint8_t PortPriority = 0x4E;
} PortCode;

enum class Poe_Status { disable, enable, unknown };
// enum class Poe_Delay { disable, enable, unknown };
enum class Max_Power { is15W, is30W, is45W, is60W, is90W, is30W_AT, unknown };
enum class Legacy_Detect { disable, enable, unknown };
enum class Matrix_Num { is2p, is4p, unknown };
enum class Port_Priority { Critical, High, Low ,unknown};
enum class LED_Status { disable, enable, withPower };
typedef struct PortInfo {
    std::string Interface;
    Poe_Status poe_Status;
    // Poe_Delay poe_Delay;
    double Current;
    double Voltage;
    double Power;
    Max_Power maxPower;
    double Power_MaxPower;
    std::string devicePSU = "150W";
    double Power_devicePSU;
    Legacy_Detect legacy_Detect;
    Matrix_Num matrix_Num;
    Port_Priority port_Priority;
    // double Temperature;
} PortInfo;

extern const InputMessage get_BT_Port_Parameters;
extern const InputMessage get_BT_Port_Measurements;
extern const InputMessage set_BT_Port_Parameters;

extern const std::unordered_set<uint8_t> poe2pEnableCodes;
extern const std::unordered_set<uint8_t> poe4pEnableCodes;
extern const std::unordered_set<uint8_t> poeForceEnableCodes;
extern const std::unordered_set<uint8_t> poeDisableCodes;
extern const std::unordered_set<uint8_t> poeUnknownCodes;
extern const std::unordered_set<uint8_t> is90W4PCodes;
extern const std::unordered_set<uint8_t> is60W4PCodes;
extern const std::unordered_set<uint8_t> is30W4PCodes;
extern const std::unordered_set<uint8_t> is15W4PCodes;
extern const std::unordered_set<uint8_t> is45W2PCodes;
extern const std::unordered_set<uint8_t> is30W2PCodes;
extern const std::unordered_set<uint8_t> is15W2PCodes;
extern const std::unordered_set<uint8_t> LegacyEnableCodes;
extern const std::unordered_set<uint8_t> LegacyDisableCodes;