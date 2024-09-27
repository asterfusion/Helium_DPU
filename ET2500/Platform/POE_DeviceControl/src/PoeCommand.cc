#include "PoeCommand.h"
#include "StructFormatter.h"
#include <iostream>
#include <iomanip>
#include <regex>


PoeCommand::PoeCommand() {
    for (auto interface : Interfaces) {
        PortCode thisPortCode;
        thisPortCode.interfaceAddr = interface.second;
        uint8_t EthernetX = StructFormatter::toInt(interface.first);
        allPortCode.insert(std::make_pair(EthernetX, thisPortCode));
    }
    this->powerMapping = {
    { Matrix_Num::is4p, {
        { Max_Power::is90W, 0x00 },
        { Max_Power::is60W, 0x01 },
        { Max_Power::is30W, 0x02 },
        { Max_Power::is15W, 0x03 }}},
    { Matrix_Num::is2p, {
        { Max_Power::is30W, 0x00 },
        { Max_Power::is15W, 0x03 }}} };
}

void PoeCommand::showInterfacePoe() {
    getBTPortStatus();
    getBTPortMeasurement();
    std::vector<PortInfo> allPortInfo;
    for (auto i : allPortCode) {
        allPortInfo.push_back(StructFormatter::parsePortCode(i.second));
    }
    printfAllPortsInfo(allPortInfo);
}
void PoeCommand::init() {
    btWorkSpace.initBt();
}
void PoeCommand::getBTPortStatus() {
    InputMessage temp_Get_BT_Port_Parameters = get_BT_Port_Parameters;

    for (auto& status : allPortCode) {
        PortCode& thisPortCode = status.second;
        getBTPortStatus(thisPortCode, temp_Get_BT_Port_Parameters);
    }
}
void PoeCommand::getBTPortStatus(uint8_t EthernetX) {
    InputMessage temp_Get_BT_Port_Parameters = get_BT_Port_Parameters;

    PortCode& thisPortCode = parseEthernetXtoPortCode(EthernetX);
    getBTPortStatus(thisPortCode, temp_Get_BT_Port_Parameters);
}


void PoeCommand::getBTPortMeasurement() {
    InputMessage temp_Get_BT_Port_Measurements = get_BT_Port_Measurements;

    for (auto& status : allPortCode) {
        PortCode& thisPortCode = status.second;
        getBTPortMeasurement(thisPortCode, temp_Get_BT_Port_Measurements);
    }
}
void PoeCommand::getBTPortMeasurement(uint8_t EthernetX) {
    InputMessage temp_Get_BT_Port_Measurements = get_BT_Port_Measurements;

    auto it = allPortCode.find(EthernetX);
    if (it == allPortCode.end()) {
        LOG(ERROR) << "Port not found: " << static_cast<int>(EthernetX);
    }
    PortCode& thisPortCode = it->second;
    getBTPortMeasurement(thisPortCode, temp_Get_BT_Port_Measurements);
}


void PoeCommand::setBTPortEnable(bool isEnable) {
    InputMessage temp_Set_BT_Port_Parameters = set_BT_Port_Parameters;

    for (auto& status : allPortCode) {
        PortCode& thisPortCode = status.second;
        setBTPortParameters(thisPortCode, temp_Set_BT_Port_Parameters, isEnable);
    }
}

void PoeCommand::setBTPortEnable(uint8_t EthernetX, bool isEnable) {
    InputMessage temp_Set_BT_Port_Parameters = set_BT_Port_Parameters;
    PortCode& thisPortCode = parseEthernetXtoPortCode(EthernetX);
    setBTPortParameters(thisPortCode, temp_Set_BT_Port_Parameters, isEnable);
}



void PoeCommand::setBTPortMaxpower(Max_Power maxPower) {
    InputMessage temp_Set_BT_Port_Parameters = set_BT_Port_Parameters;

    for (auto& status : allPortCode) {
        PortCode& thisPortCode = status.second;
        setBTPortParameters(thisPortCode, temp_Set_BT_Port_Parameters, maxPower);
    }
}

void PoeCommand::setBTPortMaxpower(uint8_t EthernetX, Max_Power maxPower) {
    InputMessage temp_Set_BT_Port_Parameters = set_BT_Port_Parameters;
    PortCode& thisPortCode = parseEthernetXtoPortCode(EthernetX);
    setBTPortParameters(thisPortCode, temp_Set_BT_Port_Parameters, maxPower);
}



void PoeCommand::setBTPortPriority(Port_Priority port_Priority) {
    InputMessage temp_Set_BT_Port_Parameters = set_BT_Port_Parameters;

    for (auto& status : allPortCode) {
        PortCode& thisPortCode = status.second;
        setBTPortParameters(thisPortCode, temp_Set_BT_Port_Parameters, port_Priority);
    }
}

void PoeCommand::setBTPortPriority(uint8_t EthernetX, Port_Priority port_Priority) {
    InputMessage temp_Set_BT_Port_Parameters = set_BT_Port_Parameters;
    PortCode& thisPortCode = parseEthernetXtoPortCode(EthernetX);
    setBTPortParameters(thisPortCode, temp_Set_BT_Port_Parameters, port_Priority);
}


void PoeCommand::setBTPortLegacy(Legacy_Detect legacy_Detect) {
    InputMessage temp_Set_BT_Port_Parameters = set_BT_Port_Parameters;

    for (auto& status : allPortCode) {
        PortCode& thisPortCode = status.second;
        setBTPortParameters(thisPortCode, temp_Set_BT_Port_Parameters, legacy_Detect);
    }
}
void PoeCommand::setBTPortLegacy(uint8_t EthernetX, Legacy_Detect legacy_Detect) {
    InputMessage temp_Set_BT_Port_Parameters = set_BT_Port_Parameters;
    PortCode& thisPortCode = parseEthernetXtoPortCode(EthernetX);
    setBTPortParameters(thisPortCode, temp_Set_BT_Port_Parameters, legacy_Detect);
}

void PoeCommand::getBTPortStatus(PortCode& thisPortCode, InputMessage& message) {
    try {
        message.send_04sub2 = thisPortCode.interfaceAddr;
        OutputMessage outputMessage = btWorkSpace.parsesExecBt(message);

        thisPortCode.PortStatus = outputMessage.read_02sub;
        thisPortCode.PortOperationMode = outputMessage.read_05data;
        thisPortCode.PortPriority = outputMessage.read_07data;
    }
    catch (const std::exception& e) {
        LOG(FATAL) << e.what();
    }
}
void PoeCommand::getBTPortMeasurement(PortCode& thisPortCode, InputMessage& message) {
    try {
        message.send_04sub2 = thisPortCode.interfaceAddr;
        OutputMessage outputMessage = btWorkSpace.parsesExecBt(message);

        thisPortCode.Current = (static_cast<uint16_t>(outputMessage.read_04sub2) << 8) | outputMessage.read_05data;
        thisPortCode.Voltage = (static_cast<uint16_t>(outputMessage.read_09data) << 8) | outputMessage.read_10data;
        thisPortCode.Power = (static_cast<uint16_t>(outputMessage.read_06data) << 8) | outputMessage.read_07data;
    }
    catch (const std::exception& e) {
        LOG(FATAL) << e.what();
    }
}
void PoeCommand::setBTPortParameters(PortCode& thisPortCode, InputMessage& message, bool isEnable) {
    try {
        message.send_04sub2 = thisPortCode.interfaceAddr;
        message.send_05data = (isEnable) ? 0x01 : 0x00;
        btWorkSpace.parsesExecBt(message);
    }
    catch (const std::exception& e) {
        LOG(FATAL) << e.what();
    }
}
void PoeCommand::setBTPortParameters(PortCode& thisPortCode, InputMessage& message, Max_Power maxPower) {
    try {
        message.send_04sub2 = thisPortCode.interfaceAddr;
        // need Matrix Legacy Power
        uint8_t thisEthernetX = StructFormatter::toInt(StructFormatter::parseInterface(thisPortCode.interfaceAddr));
        getBTPortStatus(thisEthernetX);
        Legacy_Detect thisLegacyDetect = StructFormatter::parseLegacyDetect(thisPortCode.PortOperationMode);
        Matrix_Num thisMatrixNum = StructFormatter::parseMatrix(thisPortCode.PortStatus);
        if (maxPower == Max_Power::is30W_AT) {
            message.send_07data = (thisLegacyDetect == Legacy_Detect::disable) ? 0x23 : 0x21;
            btWorkSpace.parsesExecBt(message);
            return;
        }
        else {
            message.send_07data = (thisLegacyDetect == Legacy_Detect::disable) ? 0x00 : 0x10;
        }
        auto matrixIt = powerMapping.find(thisMatrixNum);
        if (matrixIt != powerMapping.end()) {
            auto powerIt = matrixIt->second.find(maxPower);
            if (powerIt != matrixIt->second.end()) {
                message.send_07data += powerIt->second;
            }
            else {
                LOG(WARNING) <<"Ethernet" << thisEthernetX << " Matrix " << StructFormatter::toString(thisMatrixNum) << " doesn't have MaxPower " << StructFormatter::toString(maxPower);
            }
        }
        else {
            LOG(WARNING) << "Ethernet" << thisEthernetX << " Matrix " << StructFormatter::toString(thisMatrixNum) << " Please Start POE First.";
            return;
        }
        btWorkSpace.parsesExecBt(message);
    }
    catch (const std::exception& e) {
        LOG(FATAL) << e.what();
    }
}
void PoeCommand::setBTPortParameters(PortCode& thisPortCode, InputMessage& message, Port_Priority port_Priority) {
    try {
        message.send_04sub2 = thisPortCode.interfaceAddr;
        std::map<Port_Priority, uint8_t> priorityMapping = {
           { Port_Priority::Critical, 0x01 },
           { Port_Priority::High, 0x02 },
           { Port_Priority::Low, 0x03 }
        };
        auto it = priorityMapping.find(port_Priority);
        if (it != priorityMapping.end()) {
            message.send_09data = it->second;
        }
        else {
            LOG(ERROR) << "Unknown Port Priority";
        }
        btWorkSpace.parsesExecBt(message);
    }
    catch (const std::exception& e) {
        LOG(FATAL) << e.what();
    }
}
void PoeCommand::setBTPortParameters(PortCode& thisPortCode, InputMessage& message, Legacy_Detect legacy_Detect) {
    try {
        message.send_04sub2 = thisPortCode.interfaceAddr;
        // need Matrix Legacy Power
        uint8_t thisEthernetX = StructFormatter::toInt(StructFormatter::parseInterface(thisPortCode.interfaceAddr));
        getBTPortStatus(thisEthernetX);
        Matrix_Num thisMatrixNum = StructFormatter::parseMatrix(thisPortCode.PortStatus);
        Max_Power maxPower = StructFormatter::parseMaxPower(thisMatrixNum, thisPortCode.PortOperationMode);
        message.send_07data = (legacy_Detect == Legacy_Detect::disable) ? 0x00 : 0x10;
        auto matrixIt = powerMapping.find(thisMatrixNum);
        if (matrixIt != powerMapping.end()) {
            auto powerIt = matrixIt->second.find(maxPower);
            if (powerIt != matrixIt->second.end()) {
                message.send_07data += powerIt->second;
            }
            else {
                LOG(FATAL) << "Ethernet" << thisEthernetX << " Matrix " << StructFormatter::toString(thisMatrixNum) << " don't have MaxPower " << StructFormatter::toString(maxPower);
            }
        }
        else {
            LOG(WARNING) << "Ethernet" << thisEthernetX << "Matrix " << StructFormatter::toString(thisMatrixNum) << " Please Start POE First.";
        }
        btWorkSpace.parsesExecBt(message);
    }
    catch (const std::exception& e) {
        LOG(FATAL) << e.what();
    }
}
void PoeCommand::printfAllPortsInfo(const std::vector<PortInfo>& allPortInfo) {
    double totalPower = 0.0;
    std::cout << std::right
        << std::setw(12) << "Interface"
        << std::setw(13) << "Poe_Status"
        //   << std::setw(12) << "Poe_Delay"
        << std::setw(13) << "Current(A)"
        << std::setw(13) << "Voltage(V)"
        << std::setw(11) << "Power(W)"
        << std::setw(14) << "MaxPower(W)"
        << std::setw(17) << "Power/MaxPower"
        << std::setw(18) << "Power/DevicePSU"
        << std::setw(16) << "Legacy_detect"
        << std::setw(11) << "Priority" << std::endl;

    std::cout << std::string(140, '-') << std::endl;

    for (const auto& portInfo : allPortInfo) {

        std::cout << std::right
            << std::setw(12) << portInfo.Interface
            << std::setw(12) << StructFormatter::toString(portInfo.poe_Status)
            //   << std::setw(12) << status.PoeDelay
            << std::fixed << std::setprecision(3)
            << std::setw(13) << portInfo.Current
            << std::fixed << std::setprecision(1)
            << std::setw(13) << portInfo.Voltage
            << std::setw(11) << portInfo.Power
            << std::setw(14) << StructFormatter::toString(portInfo.maxPower)
            << std::fixed << std::setprecision(2)
            << std::setw(15) << portInfo.Power_MaxPower * 100 << "%"
            << std::setw(18) << portInfo.Power_devicePSU * 100 << "%"
            << std::setw(16) << StructFormatter::toString(portInfo.legacy_Detect)
            << std::setw(13) << StructFormatter::toString(portInfo.port_Priority)
            << std::endl;
        totalPower += portInfo.Power;
    }
    std::cout << std::string(140, '-') << std::endl;
    std::cout << std::fixed << std::setprecision(1)
        << "Total Ports Power is: " << totalPower << "w" << std::endl
        << "The maximum POEs Power of the device is: 150w" << std::endl
        << "the Ratio of(Total Ports Power/maximum POEs Power) is :" << totalPower / 1.5 << "%" << std::endl
        << std::defaultfloat;
}

PortCode& PoeCommand::parseEthernetXtoPortCode(uint8_t EthernetX) {
    auto it = allPortCode.find(EthernetX);
    if (it == allPortCode.end()) {
        LOG(ERROR) << "Port not found: " << static_cast<int>(EthernetX);
    }
    return it->second;
}
