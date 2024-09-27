#pragma once
#include <string>
#include "ExecBase.h"
#include "Utils.h"

/**
 * @class LedCommand
 * @brief Class for executing LED commands on network interfaces.
 *
 * The LedCommand class provides methods to control the LED status on all
 * available network interfaces or a specific one. It allows enabling,
 * disabling, or setting the LED to a power mode.
 */
class LedCommand : public ExecBase {
public:
    /**
     * @brief Constructs a LedCommand object.
     *
     * Initializes the program name used for executing LED commands.
     */
    LedCommand();

    /**
     * @brief Executes LED command on all interfaces.
     *
     * @param LEDStatus The desired LED status (enable, disable, or with power).
     */
    void execLED(LED_Status LEDStatus);

    /**
     * @brief Executes LED command on a specific interface.
     *
     * @param EthernetX The identifier for the specific Ethernet interface.
     * @param LEDStatus The desired LED status (enable, disable, or with power).
     */
    void execLED(uint8_t EthernetX, LED_Status LEDStatus);

private:
    /**
     * @brief Parses the EthernetX identifier to corresponding command arguments.
     *
     * -a Used to distinguish network port speed
     * -b Sort within the same rate group based on PCI address
     *
     * @param EthernetX The identifier for the Ethernet interface.
     * @return A pair of integers representing command arguments.
     */
    std::pair<int, int> parsesEthernetXtoArgsAB(uint8_t EthernetX);

private:
    std::string programName; ///< The name of the program used to execute LED commands.
};
