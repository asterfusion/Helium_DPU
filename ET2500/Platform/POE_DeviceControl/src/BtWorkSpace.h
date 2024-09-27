#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include "Utils.h"
#include "ExecBase.h"
/**
 * @class BtWorkSpace
 * @brief A singleton class that manages the BT workspace operations.
 *
 * This class provides functionalities to execute and parse commands related to BT API.
 * It encapsulates methods for initializing the BT API system and processing input messages.
 *
 */
class BtWorkSpace : public ExecBase {
public:
    /**
     * @brief Get the singleton instance of the BtWorkSpace class.
     * @return Reference to the instance of BtWorkSpace.
     */
    static BtWorkSpace& getInstance();

    // Deleted copy constructor and assignment operator to prevent copies.
    BtWorkSpace(BtWorkSpace const&) = delete;
    void operator=(BtWorkSpace const&) = delete;

    /**
     * @brief Execute a command based on an input message.
     * @param input The input message containing the command.
     * @return The result of the command execution as a string.
     */
    std::string execBt(const InputMessage& input);

    /**
     * @brief Execute a command based on a vector of arguments.
     * @param args The vector of arguments for the command.
     * @return The result of the command execution as a string.
     */
    std::string execBt(const std::vector<uint8_t>& args);

    /**
     * @brief Execute a command based on a vector of string arguments.
     * @param charArray The vector of string arguments for the command.
     * @return The result of the command execution as a string.
     */
    std::string execBt(const std::vector<std::string>& charArray);

    /**
     * @brief Parse an input message and return an output message.
     * @param input The input message to be parsed.
     * @return The parsed output message.
     */
    OutputMessage parsesExecBt(const InputMessage& input);

    /**
     * @brief Parse a vector of arguments and return an output message.
     * @param args The vector of arguments to be parsed.
     * @return The parsed output message.
     */
    OutputMessage parsesExecBt(const std::vector<uint8_t>& args);

    /**
     * @brief Parse a vector of string arguments and return an output message.
     * @param charArray The vector of string arguments to be parsed.
     * @return The parsed output message.
     */
    OutputMessage parsesExecBt(const std::vector<std::string>& charArray);

    /**
     * @brief Initialize the BT system.
     * @return True if initialization is successful, false otherwise.
     */
    bool initBt();

private:
    /**
     * @brief Constructor for BtWorkSpace.
     */
    BtWorkSpace();

private:
    std::string programName; ///< Name of the program.
};
