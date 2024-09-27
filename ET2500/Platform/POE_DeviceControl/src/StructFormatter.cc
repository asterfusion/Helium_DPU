#include "StructFormatter.h"
#include <iostream>
#include <sstream>
#include <cstdio>
#include <iomanip>
#include <regex>
std::vector<uint8_t> StructFormatter::parseInput(const InputMessage& input) {
    return {
        input.send_00key, input.send_01echo, input.send_02sub,
        input.send_03sub1, input.send_04sub2, input.send_05data,
        input.send_06data, input.send_07data, input.send_08data,
        input.send_09data, input.send_10data, input.send_11data,
        input.send_12data
    };
}
std::vector<std::string> StructFormatter::toString(const std::vector<uint8_t>& tempArgs) {
    std::vector<std::string> strArgs;
    for (const auto& byte : tempArgs) {
        std::ostringstream oss;
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        strArgs.push_back(oss.str());
    }

    return strArgs;
}
std::vector<uint8_t> StructFormatter::parseHexDataFromSection(const uint8_t number, const std::string& input, const std::string& sectionName) {
    std::vector<uint8_t> data;

    std::string sectionPattern = sectionName + R"(\s*([0-9a-fA-Fx\s]+))";
    std::regex sectionRegex(sectionPattern);
    std::smatch match;

    if (std::regex_search(input, match, sectionRegex)) {
        std::string hexString = match[1];
        std::regex hexRegex(R"(0x([0-9a-fA-F]{2}))");
        std::smatch hexMatch;
        std::string::const_iterator searchStart(hexString.cbegin());

        while (std::regex_search(searchStart, hexString.cend(), hexMatch, hexRegex) && data.size() < number) {
            uint8_t value = static_cast<uint8_t>(std::stoi(hexMatch[1], nullptr, 16));
            data.push_back(value);
            searchStart = hexMatch.suffix().first;
        }
    }
    else {
        LOG(FATAL) << "Section not found: " << sectionName;
    }

    return data;
}

OutputMessage StructFormatter::parseString(const std::string& shellString) {
    std::regex regex(R"(pmsg->code:(\d+))");
    std::smatch match;
    uint8_t pmsgCode;
    if (std::regex_search(shellString, match, regex)) {
        pmsgCode = std::stoi(match[1], nullptr, 10);
    }
    else {
        pmsgCode = 0;
        LOG(FATAL) << "pmsg->code not found.";
    }
    std::vector<uint8_t> sendData = StructFormatter::parseHexDataFromSection(13, shellString, "send msg:");
    std::vector<uint8_t> readData = StructFormatter::parseHexDataFromSection(13, shellString, "read back:");
    OutputMessage message;
    populateOutputMessage(message, sendData, readData, pmsgCode);
    return message;
}
PortInfo StructFormatter::parsePortCode(const PortCode& portCode) {
    PortInfo portInfo;
    portInfo.Interface = parseInterface(portCode.interfaceAddr);
    portInfo.poe_Status = parsePoeStatus(portCode.PortStatus);
    portInfo.Current = convertToAmps(portCode.Current);
    portInfo.Voltage = convertToVolts(portCode.Voltage);
    portInfo.Power = convertToWatts(portCode.Power);
    portInfo.matrix_Num = parseMatrix(portCode.PortStatus);
    portInfo.maxPower = parseMaxPower(portInfo.matrix_Num, portCode.PortOperationMode);
    portInfo.Power_MaxPower = calculatePower_MaxPower(portInfo.Power, portInfo.maxPower);
    portInfo.Power_devicePSU = calculatePower_DevicePSU(portInfo.Power);
    portInfo.legacy_Detect = parseLegacyDetect(portCode.PortOperationMode);
    portInfo.port_Priority = parsePortPriority(portCode.PortPriority);
    return portInfo;
}
std::string StructFormatter::parseInterface(uint8_t interfaceAddr) {
    for (const auto& interface : Interfaces) {
        if (interface.second == interfaceAddr) {
            return interface.first;
            break;
        }
    }
    LOG(FATAL) << "Can not parseInterface";
    return "";
}
Poe_Status StructFormatter::parsePoeStatus(uint8_t portStatus) {
    if (poe2pEnableCodes.count(portStatus)) {
        return Poe_Status::enable;
    }
    else if (poe4pEnableCodes.count(portStatus)) {
        return Poe_Status::enable;
    }
    else if (poeDisableCodes.count(portStatus)) {
        return Poe_Status::disable;
    }
    else {
        return Poe_Status::unknown;
    }
}
Matrix_Num StructFormatter::parseMatrix(uint8_t portStatus) {
    if (poe2pEnableCodes.count(portStatus)) {
        return Matrix_Num::is2p;
    }
    else if (poe4pEnableCodes.count(portStatus)) {
        return Matrix_Num::is4p;
    }
    else return Matrix_Num::unknown;
}
double StructFormatter::convertToAmps(uint16_t current_mA) {
    return static_cast<double>(current_mA) / 1000.0;
}
double StructFormatter::convertToVolts(uint16_t voltage_0_1V) {
    return static_cast<double>(voltage_0_1V) * 0.1;
}
double StructFormatter::convertToWatts(uint16_t wattage_0_1V) {
    return static_cast<double>(wattage_0_1V) * 0.1;
}
Max_Power StructFormatter::parseMaxPower(Matrix_Num matrix_Num, uint8_t portOperationMode) {
    if (matrix_Num == Matrix_Num::is2p) {
        if (is15W2PCodes.count(portOperationMode)) return Max_Power::is15W;
        if (is30W2PCodes.count(portOperationMode)) return Max_Power::is30W;
        if (is45W2PCodes.count(portOperationMode)) return Max_Power::is45W;
    }
    else if (matrix_Num == Matrix_Num::is4p) {
        if (is15W4PCodes.count(portOperationMode)) return Max_Power::is15W;
        if (is30W4PCodes.count(portOperationMode)) return Max_Power::is30W;
        if (is60W4PCodes.count(portOperationMode)) return Max_Power::is60W;
        if (is90W4PCodes.count(portOperationMode)) return Max_Power::is90W;
    }
    return Max_Power::unknown;
}
double StructFormatter::calculatePower_MaxPower(double power, Max_Power maxPower) {
    switch (maxPower) {
    case Max_Power::is15W: return power / 15.0;
    case Max_Power::is30W: return power / 30.0;
    case Max_Power::is45W: return power / 45.0;
    case Max_Power::is60W: return power / 60.0;
    case Max_Power::is90W: return power / 90.0;
    default: return 0;
    }
}
double StructFormatter::calculatePower_DevicePSU(double power) {
    return power / 150.0;
}
Legacy_Detect StructFormatter::parseLegacyDetect(uint8_t portOperationMode) {
    if (LegacyEnableCodes.count(portOperationMode)) {
        return Legacy_Detect::enable;
    }
    else if (LegacyDisableCodes.count(portOperationMode)) {
        return Legacy_Detect::disable;
    }
    else {
        return Legacy_Detect::unknown;
    }
}
Port_Priority StructFormatter::parsePortPriority(uint8_t portPriority) {
    switch (portPriority) {
    case 0x01: return Port_Priority::Critical;
    case 0x02: return Port_Priority::High;
    case 0x03: return Port_Priority::Low;
    default: return Port_Priority::unknown;
    }
}
std::string StructFormatter::toString(Poe_Status status) {
    switch (status) {
    case Poe_Status::disable: return "disable";
    case Poe_Status::enable: return "enable";
    default: return "unknown";
    }
}

std::string StructFormatter::toString(Max_Power power) {
    switch (power) {
    case Max_Power::is15W: return "15W";
    case Max_Power::is30W: return "30W";
    case Max_Power::is45W: return "45W";
    case Max_Power::is60W: return "60W";
    case Max_Power::is90W: return "90W";
    case Max_Power::is30W_AT: return "30W-AT";
    case Max_Power::unknown: return "unknown";
    default: return "unknown";
    }
}

std::string StructFormatter::toString(Legacy_Detect detect) {
    switch (detect) {
    case Legacy_Detect::disable: return "disable";
    case Legacy_Detect::enable: return "enable";
    case Legacy_Detect::unknown: return "unknown";
    default: return "unknown";
    }
}

std::string StructFormatter::toString(Matrix_Num matrix) {
    switch (matrix) {
    case Matrix_Num::is2p: return "2p";
    case Matrix_Num::is4p: return "4p";
    case Matrix_Num::unknown: return "unknown";
    default: return "unknown";
    }
}
std::string StructFormatter::toString(Port_Priority port_Priority) {
    switch (port_Priority) {
    case Port_Priority::Low: return "Low";
    case Port_Priority::High: return "High";
    case Port_Priority::Critical:return "Critical";
    case Port_Priority::unknown:return "unknown";
    default: return "unknown";
    }
}

uint8_t StructFormatter::toInt(const std::string& EthernetX) {
    std::regex regex(R"(\d+)");
    std::smatch match;
    if (std::regex_search(EthernetX, match, regex)) {
        return std::stoi(match.str());
    }
    else {
        LOG(FATAL) << "No EthernetX:" << EthernetX;
        return 0;
    }
}
void StructFormatter::populateOutputMessage(OutputMessage& message, const std::vector<uint8_t>& sendData, const std::vector<uint8_t>& readData, uint8_t pmsgCode) {
    message = {
        .pmsgCode = pmsgCode,
        .send_00key = sendData[0],
        .send_01echo = sendData[1],
        .send_02sub = sendData[2],
        .send_03sub1 = sendData[3],
        .send_04sub2 = sendData[4],
        .send_05data = sendData[5],
        .send_06data = sendData[6],
        .send_07data = sendData[7],
        .send_08data = sendData[8],
        .send_09data = sendData[9],
        .send_10data = sendData[10],
        .send_11data = sendData[11],
        .send_12data = sendData[12],
        .read_00key = readData[0],
        .read_01echo = readData[1],
        .read_02sub = readData[2],
        .read_03sub1 = readData[3],
        .read_04sub2 = readData[4],
        .read_05data = readData[5],
        .read_06data = readData[6],
        .read_07data = readData[7],
        .read_08data = readData[8],
        .read_09data = readData[9],
        .read_10data = readData[10],
        .read_11data = readData[11],
        .read_12data = readData[12] };
}
