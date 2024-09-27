#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <unordered_map>
#include "LedCommand.h"
#include "PoeCommand.h"

/*
poe             init
poe             show
poe             enable|disable          all|EthernetX
maxpower        {60w|30w|15w|30w-at}    all|EthernetX
priority        {low|high|critical}     all|EthernetX
legacydetect    {enable|disable}        all|EthernetX
led             on|off                  all|EthernetX
*/
enum CommandType {
    HELP_COMMAND,
    POE_INIT,
    POE_SHOW,
    POE_ENABLE,
    POE_DISABLE,
    MAX_POWER_15W,
    MAX_POWER_30W,
    MAX_POWER_60W,
    MAX_POWER_30W_AT,
    PRIORITY_LOW,
    PRIORITY_HIGH,
    PRIORITY_CRITICAL,
    LEGACY_DETECT_ENABLE,
    LEGACY_DETECT_DISABLE,
    LED_ON,
    LED_OFF,
    INVALID_COMMAND,
};
/**
 * @struct Command
 * @brief Represents a parsed command and its associated argument.
 *
 * This structure is used to hold the type of command as well as any arguments
 * that may be associated with it. It is utilized in the command parsing and
 * execution processes within the UserInteraction class.
 */
struct Command {
    CommandType type;       ///< The type of the command, represented as a CommandType enumeration.
    std::string argument;   ///< The argument associated with the command, if any.
};

/**
 * @class UserInteraction
 * @brief Handles user commands and interactions for the PoE system.
 *
 * This class is responsible for parsing user input commands, executing the corresponding
 * actions, and displaying help information. It interacts with the `LedCommand` and
 * `PoeCommand` classes to perform various operations related to Power over Ethernet (PoE)
 * management and LED control.
 */
class UserInteraction {
public:
    /**
     * @brief Executes the command based on user input.
     * @param argc The number of command-line arguments.
     * @param argv The command-line arguments.
     *
     * This method parses the command-line arguments and executes the corresponding command.
     */
    void Exec(int argc, char* argv[]);

    /**
     * @brief Executes the specified command.
     * @param poeCommand The command to be executed.
     *
     * This method determines the action to be performed based on the command type and
     * invokes the necessary methods from the `PoeCommand` and `LedCommand` classes.
     */
    void execCommand(Command& poeCommand);

    /**
     * @brief Parses command-line arguments into a Command structure.
     * @param argc The number of command-line arguments.
     * @param argv The command-line arguments.
     * @return The parsed command with its type and argument.
     *
     * This method analyzes the provided arguments and maps them to a corresponding
     * command type. It returns an invalid command if the arguments do not match any
     * known command structure.
     */
    Command parseCommand(int argc, char* argv[]);

private:
    /**
     * @brief Displays help information for available commands.
     *
     * This method outputs a list of all available commands and their usage to the
     * console, providing guidance to the user.
     */
    void showHelp();

    /**
     * @brief Converts a string to lowercase.
     * @param str The input string.
     * @return The lowercase version of the input string.
     *
     * This helper function is used to facilitate case-insensitive command parsing.
     */
    std::string toLower(const std::string& str);

    LedCommand led; ///< Instance of LedCommand to control LED operations.
    PoeCommand poe; ///< Instance of PoeCommand to manage PoE functionalities.
};
