#include "UserInteraction.h"
#include "StructFormatter.h"
void UserInteraction::Exec(int argc, char* argv[]) {
    Command command = parseCommand(argc, argv);
    execCommand(command);
}

void UserInteraction::execCommand(Command& command) {
    switch (command.type) {
    case CommandType::HELP_COMMAND:
        showHelp();
        break;
    case CommandType::POE_SHOW:
        LOG(INFO) << "Showing POE status...";
        poe.showInterfacePoe();
        break;

    case CommandType::POE_INIT:
        LOG(INFO) << "Initializing POE...";
        poe.init();
        break;

    case CommandType::POE_ENABLE:
        LOG(INFO) << "Enabling POE on port: " << command.argument;
        if (command.argument == "all") {
            poe.setBTPortEnable(true);
        }
        else {
            poe.setBTPortEnable(StructFormatter::toInt(command.argument), true);
        }
        break;

    case CommandType::POE_DISABLE:
        LOG(INFO) << "Disabling POE on port: " << command.argument;
        if (command.argument == "all") {
            poe.setBTPortEnable(false);
        }
        else {
            poe.setBTPortEnable(StructFormatter::toInt(command.argument), false);
        }
        break;

    case CommandType::LED_ON:
        LOG(INFO) << "Turning on LED for port: " << command.argument;
        if (command.argument == "all") {
            led.execLED(LED_Status::enable);
        }
        else {
            led.execLED(StructFormatter::toInt(command.argument), LED_Status::enable);
        }
        break;

    case CommandType::LED_OFF:
        LOG(INFO) << "Turning off LED for port: " << command.argument;
        if (command.argument == "all") {
            led.execLED(LED_Status::disable);
        }
        else {
            led.execLED(StructFormatter::toInt(command.argument), LED_Status::disable);
        }
        break;

    case CommandType::MAX_POWER_15W:
        LOG(INFO) << "Setting max power to 15W for port: " << command.argument;
        if (command.argument == "all") {
            poe.setBTPortMaxpower(Max_Power::is15W);
        }
        else {
            poe.setBTPortMaxpower(StructFormatter::toInt(command.argument), Max_Power::is15W);
        }
        break;

    case CommandType::MAX_POWER_30W:
        LOG(INFO) << "Setting max power to 30W for port: " << command.argument;
        if (command.argument == "all") {
            poe.setBTPortMaxpower(Max_Power::is30W);
        }
        else {
            poe.setBTPortMaxpower(StructFormatter::toInt(command.argument), Max_Power::is30W);
        }
        break;

    case CommandType::MAX_POWER_60W:
        LOG(INFO) << "Setting max power to 60W for port: " << command.argument;
        if (command.argument == "all") {
            poe.setBTPortMaxpower(Max_Power::is60W);
        }
        else {
            poe.setBTPortMaxpower(StructFormatter::toInt(command.argument), Max_Power::is60W);
        }
        break;

    case CommandType::MAX_POWER_30W_AT:
        LOG(INFO) << "Setting max power to 30W-at for port: " << command.argument;
        if (command.argument == "all") {
            poe.setBTPortMaxpower(Max_Power::is30W_AT);
        }
        else {
            poe.setBTPortMaxpower(StructFormatter::toInt(command.argument), Max_Power::is30W_AT);
        }
        break;

    case CommandType::PRIORITY_LOW:
        LOG(INFO) << "Setting priority to low for port: " << command.argument;
        if (command.argument == "all") {
            poe.setBTPortPriority(Port_Priority::Low);
        }
        else {
            poe.setBTPortPriority(StructFormatter::toInt(command.argument), Port_Priority::Low);
        }
        break;

    case CommandType::PRIORITY_HIGH:
        LOG(INFO) << "Setting priority to high for port: " << command.argument;
        if (command.argument == "all") {
            poe.setBTPortPriority(Port_Priority::High);
        }
        else {
            poe.setBTPortPriority(StructFormatter::toInt(command.argument), Port_Priority::High);
        }
        break;

    case CommandType::PRIORITY_CRITICAL:
        LOG(INFO) << "Setting priority to critical for port: " << command.argument;
        if (command.argument == "all") {
            poe.setBTPortPriority(Port_Priority::Critical);
        }
        else {
            poe.setBTPortPriority(StructFormatter::toInt(command.argument), Port_Priority::Critical);
        }
        break;

    case CommandType::LEGACY_DETECT_ENABLE:
        LOG(INFO) << "Enabling legacy detect on port: " << command.argument;
        if (command.argument == "all") {
            poe.setBTPortLegacy(Legacy_Detect::enable);
        }
        else {
            poe.setBTPortLegacy(StructFormatter::toInt(command.argument), Legacy_Detect::enable);
        }
        break;

    case CommandType::LEGACY_DETECT_DISABLE:
        LOG(INFO) << "Disabling legacy detect on port: " << command.argument;
        if (command.argument == "all") {
            poe.setBTPortLegacy(Legacy_Detect::disable);
        }
        else {
            poe.setBTPortLegacy(StructFormatter::toInt(command.argument), Legacy_Detect::disable);
        }
        break;

    case CommandType::INVALID_COMMAND:
    default:
        LOG(FATAL) << "Invalid command or unknown command type!";
        break;
    }
}

std::string UserInteraction::toLower(const std::string& str) {
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return lowerStr;
}

Command UserInteraction::parseCommand(int argc, char* argv[]) {
    if (argc < 2) {
        return { INVALID_COMMAND, "" };
    }

    std::string cmd1 = toLower(argv[1]);

    if (cmd1 == "help") {
        return { HELP_COMMAND, "" };
    }
    if (cmd1 == "poe") {
        if (argc == 3 && toLower(argv[2]) == "show")
            return { POE_SHOW, "" };
        if (argc == 3 && toLower(argv[2]) == "init")
            return { POE_INIT, "" };
        if (argc == 4 && toLower(argv[2]) == "enable") {
            return { POE_ENABLE, argv[3] };
        }
        if (argc == 4 && toLower(argv[2]) == "disable") {
            return { POE_DISABLE, argv[3] };
        }
    }
    if (cmd1 == "maxpower" && argc == 4) {
        if (toLower(argv[2]) == "60w")
            return { MAX_POWER_60W, argv[3]};
        if (toLower(argv[2]) == "30w")
            return { MAX_POWER_30W, argv[3] };
        if (toLower(argv[2]) == "15w")
            return { MAX_POWER_15W, argv[3] };
        if (toLower(argv[2]) == "30w-at")
            return { MAX_POWER_30W_AT, argv[3] };
    }
    if (cmd1 == "priority" && argc == 4) {
        if (toLower(argv[2]) == "low")
            return { PRIORITY_LOW, argv[3] };
        if (toLower(argv[2]) == "high")
            return { PRIORITY_HIGH, argv[3] };
        if (toLower(argv[2]) == "critical")
            return { PRIORITY_CRITICAL, argv[3] };
    }
    if (cmd1 == "legacydetect" && argc == 4) {
        if (toLower(argv[2]) == "enable")
            return { LEGACY_DETECT_ENABLE, argv[3] };
        if (toLower(argv[2]) == "disable")
            return { LEGACY_DETECT_DISABLE, argv[3] };
    }
    if (cmd1 == "led" && argc == 4) {
        if (toLower(argv[2]) == "on")
            return { LED_ON, argv[3] };
        if (toLower(argv[2]) == "off")
            return { LED_OFF,argv[3] };
    }
    return { INVALID_COMMAND ,""};
}

void UserInteraction::showHelp() {
    std::cout << "Available Commands:\n\n"
        << "1. poe init\n"
        << "   Initializes the Power over Ethernet (PoE) system.\n\n"
        << "2. poe show\n"
        << "   Displays the current status of the PoE system.\n\n"
        << "3. poe enable <port>\n"
        << "   Enables PoE on the specified port. Use 'all' to enable PoE on all ports.\n"
        << "   Example: poe enable Ethernet1\n\n"
        << "4. poe disable <port>\n"
        << "   Disables PoE on the specified port. Use 'all' to disable PoE on all ports.\n"
        << "   Example: poe disable all\n\n"
        << "5. maxpower <value> <port>\n"
        << "   Sets the maximum power for the specified port. Valid values are:\n"
        << "   - 60w\n"
        << "   - 30w\n"
        << "   - 15w\n"
        << "   - 30w-at\n"
        << "   Use 'all' to set the maximum power for all ports.\n"
        << "   Example: maxpower 30w Ethernet2\n\n"
        << "6. priority <level> <port>\n"
        << "   Sets the priority level for the specified port. Valid levels are:\n"
        << "   - low\n"
        << "   - high\n"
        << "   - critical\n"
        << "   Use 'all' to set the priority for all ports.\n"
        << "   Example: priority high all\n\n"
        << "7. legacydetect <state> <port>\n"
        << "   Enables or disables legacy detection on the specified port. Valid states are:\n"
        << "   - enable\n"
        << "   - disable\n"
        << "   Use 'all' to apply to all ports.\n"
        << "   Example: legacydetect enable Ethernet3\n\n"
        << "8. led <state> <port>\n"
        << "   Controls the LED status for the specified port. Valid states are:\n"
        << "   - on\n"
        << "   - off\n"
        << "   Use 'all' to control the LED for all ports.\n"
        << "   Example: led on all\n\n";
}
