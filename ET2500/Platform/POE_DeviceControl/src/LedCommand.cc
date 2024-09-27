#include"LedCommand.h"
#include"StructFormatter.h"
#include"Utils.h"
#include<array>
#include<memory>
LedCommand::LedCommand() : programName("txcsr RPMX_MTI_MAC100X_SCRATCH") {
    if (programName.empty()) {
        LOG(ERROR) << "Invalid program name.";
    }
}
void LedCommand::execLED(LED_Status LEDStatus) {
    for (auto interface :Interfaces) {
        uint8_t EthernetX = StructFormatter::toInt(interface.first);
        execLED(EthernetX, LEDStatus);
    }
}
void LedCommand::execLED(uint8_t EthernetX, LED_Status LEDStatus) {
    std::string command = programName;

    std::pair<int, int> args = parsesEthernetXtoArgsAB(EthernetX);
    command += " -a " + std::to_string(args.first);
    command += " -b " + std::to_string(args.second);
    const std::map<LED_Status, std::string> statusCommands = {
        {LED_Status::enable, " -x 0x09"},
        {LED_Status::disable, " -x 0x08"},
        {LED_Status::withPower, " -x 0x00"} };
    auto it = statusCommands.find(LEDStatus);
    if (it != statusCommands.end()) {
        command += it->second;
    }
    else {
        LOG(ERROR) << "Invalid LED_Status: " << static_cast<int>(LEDStatus);
        return;
    }
    runCommand(command);
}

std::pair<int, int> LedCommand::parsesEthernetXtoArgsAB(uint8_t EthernetX) {

    constexpr std::array<std::pair<int, int>, 12> results = { {
        {0, 3}, {0, 0}, {0, 2}, {0, 1},
        {0, 7}, {0, 4}, {0, 6}, {0, 5},
        {1, 3}, {1, 0}, {1, 2}, {1, 1}
    } };

    if (EthernetX < results.size()) {
        return results[EthernetX];
    }
    else {
        LOG(ERROR) << "Not have Ethernet: " << static_cast<int>(EthernetX);
        return { -1, -1 };
    }
}
