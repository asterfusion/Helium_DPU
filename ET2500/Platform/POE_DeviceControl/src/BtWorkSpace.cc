#include "BtWorkSpace.h"
#include "StructFormatter.h"
#include <iostream>
#include <array>
#include <memory>

BtWorkSpace::BtWorkSpace() : programName("API_BT_Share_workspace") {
}

bool BtWorkSpace::initBt() {
    std::vector<std::string> initArry = { "-i", "et2500" };
    std::string output = execBt(initArry);
    if (output.empty()) {
        LOG(FATAL) << "Can Not Init " << programName;
        return false;
    }
    else {
        return true;
    }
}

BtWorkSpace& BtWorkSpace::getInstance() {
    static BtWorkSpace instance; 
    return instance;
}

std::string BtWorkSpace::execBt(const InputMessage& input) {
    return execBt(StructFormatter::parseInput(input));
}

std::string BtWorkSpace::execBt(const std::vector<uint8_t>& tempArgs) {
    auto strArgs = StructFormatter::toString(tempArgs);
    return execBt(strArgs);
}

std::string BtWorkSpace::execBt(const std::vector<std::string>& charArray) {
    std::string command = programName;
    for (const auto& str : charArray) {
        command += " " + str;
    }
    LOG(DEBUG) << "Command: " << command;
    return runCommand(command);
}

OutputMessage BtWorkSpace::parsesExecBt(const InputMessage& input) {
    std::string shellMsg = execBt(input);
    OutputMessage output = StructFormatter::parseString(shellMsg);
    return output;
}
OutputMessage BtWorkSpace::parsesExecBt(const std::vector<uint8_t>& args) {
    std::string shellMsg = execBt(args);
    OutputMessage output = StructFormatter::parseString(shellMsg);
    return output;
}
OutputMessage BtWorkSpace::parsesExecBt(const std::vector<std::string>& charArray) {
    std::string shellMsg = execBt(charArray);
    OutputMessage output = StructFormatter::parseString(shellMsg);
    return output;
}