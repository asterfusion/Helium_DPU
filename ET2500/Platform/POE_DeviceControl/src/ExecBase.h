#pragma once
#include <string>
#include <array>
#include <memory>
#include "Utils.h"

/**
 * @class ExecBase
 * @brief Base class for executing commands.
 *
 * This class serves as a base for all command execution classes. It provides a protected
 * method to run system commands and retrieve their output. Derived classes can utilize
 * this functionality to implement specific command logic.
 */
class ExecBase {
protected:
    /**
     * @brief Run a system command and retrieve its output.
     * @param command The command to be executed as a string.
     * @return The output of the executed command as a string.
     *
     * This method executes the given command in the system shell and captures its output.
     * It can be used by derived classes to perform various command-related operations.
     */
    std::string runCommand(const std::string& command);
};