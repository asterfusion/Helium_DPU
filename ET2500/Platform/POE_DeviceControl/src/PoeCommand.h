#pragma once
#include"Utils.h"
#include"BtWorkSpace.h"
/**
 * @brief Class for managing Power over Ethernet (PoE) commands.
 *
 * This class provides methods to initialize PoE settings, query port status,
 * measurements, and configure port parameters such as power, priority, and
 * legacy detection.
 */
class PoeCommand {
public:
    /**
     * @brief Constructs a PoeCommand object.
     *
     * Initializes the internal data structures and maps the Ethernet ports
     * to their corresponding PortCodes.
     */
    PoeCommand();

    /**
     * @brief Displays the current PoE interface status.
     *
     * This method retrieves the status and measurements of all PoE ports
     * and prints the information in a formatted manner.
     */
    void showInterfacePoe();

    /**
     * @brief Initializes the PoE settings.
     *
     * This method calls the initialization function in the BtWorkSpace
     * to set up the PoE configuration.
     */
    void init();

    /**
     * @brief Retrieves the status of all PoE ports.
     *
     * This method sends requests to all ports to retrieve their current status
     * and updates the internal data structures accordingly.
     */
    void getBTPortStatus();

    /**
     * @brief Retrieves the status of a specific PoE port.
     *
     * @param EthernetX The identifier for the Ethernet port.
     *
     * This method sends a request to the specified port to retrieve its status
     * and updates the corresponding PortCode.
     */
    void getBTPortStatus(uint8_t EthernetX);

    /**
     * @brief Retrieves the measurements for all PoE ports.
     *
     * This method sends requests to all ports to retrieve their current
     * measurement data (current, voltage, power) and updates the internal data.
     */
    void getBTPortMeasurement();

    /**
     * @brief Retrieves the measurements for a specific PoE port.
     *
     * @param EthernetX The identifier for the Ethernet port.
     *
     * This method sends a request to the specified port to retrieve its
     * measurement data and updates the corresponding PortCode.
     */
    void getBTPortMeasurement(uint8_t EthernetX);

    /**
     * @brief Enables or disables all PoE ports.
     *
     * @param isEnable True to enable all ports, false to disable them.
     *
     * This method updates the enable state for all PoE ports based on the
     * provided parameter.
     */
    void setBTPortEnable(bool isEnable);

    /**
     * @brief Enables or disables a specific PoE port.
     *
     * @param EthernetX The identifier for the Ethernet port.
     * @param isEnable True to enable the port, false to disable it.
     *
     * This method updates the enable state for the specified PoE port.
     */
    void setBTPortEnable(uint8_t EthernetX, bool isEnable);

    /**
     * @brief Sets the maximum power for all PoE ports.
     *
     * @param maxPower The maximum power level to set for all ports.
     *
     * This method updates the maximum power configuration for all PoE ports.
     */
    void setBTPortMaxpower(Max_Power maxPower);

    /**
     * @brief Sets the maximum power for a specific PoE port.
     *
     * @param EthernetX The identifier for the Ethernet port.
     * @param maxPower The maximum power level to set for the specified port.
     *
     * This method updates the maximum power configuration for the specified
     * PoE port.
     */
    void setBTPortMaxpower(uint8_t EthernetX, Max_Power maxPower);

    /**
     * @brief Sets the priority for all PoE ports.
     *
     * @param port_Priority The priority level to set for all ports.
     *
     * This method updates the priority configuration for all PoE ports.
     */
    void setBTPortPriority(Port_Priority port_Priority);

    /**
     * @brief Sets the priority for a specific PoE port.
     *
     * @param EthernetX The identifier for the Ethernet port.
     * @param port_Priority The priority level to set for the specified port.
     *
     * This method updates the priority configuration for the specified
     * PoE port.
     */
    void setBTPortPriority(uint8_t EthernetX, Port_Priority port_Priority);

    /**
     * @brief Enables or disables legacy detection for all PoE ports.
     *
     * @param legacy_Detect The legacy detection setting to apply to all ports.
     *
     * This method updates the legacy detection configuration for all PoE ports.
     */
    void setBTPortLegacy(Legacy_Detect legacy_Detect);

    /**
     * @brief Enables or disables legacy detection for a specific PoE port.
     *
     * @param EthernetX The identifier for the Ethernet port.
     * @param legacy_Detect The legacy detection setting to apply to the specified port.
     *
     * This method updates the legacy detection configuration for the specified
     * PoE port.
     */
    void setBTPortLegacy(uint8_t EthernetX, Legacy_Detect legacy_Detect);

private:
    /**
     * @brief Retrieves the status of a specific PoE port.
     *
     * @param thisPortCode Reference to the port code.
     * @param message Input message containing request details.
     *
     * This method updates the PortCode with the current status from the
     * specified port.
     */
    void getBTPortStatus(PortCode& thisPortCode, InputMessage& message);

    /**
     * @brief Retrieves measurements for a specific PoE port.
     *
     * @param thisPortCode Reference to the port code.
     * @param message Input message containing request details.
     *
     * This method updates the PortCode with the current measurements
     * (current, voltage, power) from the specified port.
     */
    void getBTPortMeasurement(PortCode& thisPortCode, InputMessage& message);

    /**
     * @brief Sets parameters for a specific PoE port based on enable state.
     *
     * @param thisPortCode Reference to the port code.
     * @param message Input message containing request details.
     * @param isEnable Enable or disable the port.
     *
     * This method sends the configuration to enable or disable the specified
     * port.
     */
    void setBTPortParameters(PortCode& thisPortCode, InputMessage& message, bool isEnable);

    /**
     * @brief Sets parameters for a specific PoE port based on maximum power.
     *
     * @param thisPortCode Reference to the port code.
     * @param message Input message containing request details.
     * @param maxPower The maximum power level to set.
     *
     * This method sends the configuration to set the maximum power for the
     * specified port.
     */
    void setBTPortParameters(PortCode& thisPortCode, InputMessage& message, Max_Power maxPower);

    /**
     * @brief Sets parameters for a specific PoE port based on priority.
     *
     * @param thisPortCode Reference to the port code.
     * @param message Input message containing request details.
     * @param port_Priority The priority level to set.
     *
     * This method sends the configuration to set the priority for the
     * specified port.
     */
    void setBTPortParameters(PortCode& thisPortCode, InputMessage& message, Port_Priority port_Priority);

    /**
     * @brief Sets parameters for a specific PoE port based on legacy detection.
     *
     * @param thisPortCode Reference to the port code.
     * @param message Input message containing request details.
     * @param legacy_Detect The legacy detection setting to apply.
     *
     * This method sends the configuration to set the legacy detection for the
     * specified port.
     */
    void setBTPortParameters(PortCode& thisPortCode, InputMessage& message, Legacy_Detect legacy_Detect);

    /**
     * @brief Prints information for all PoE ports.
     *
     * @param allPortInfo Vector containing information of all ports.
     *
     * This method formats and outputs the status and measurements of all
     * PoE ports to the console.
     */
    static void printfAllPortsInfo(const std::vector<PortInfo>& allPortInfo);

    /**
     * @brief Parses an Ethernet identifier to a corresponding PortCode.
     *
     * @param EthernetX The identifier for the Ethernet port.
     * @return Reference to the corresponding PortCode.
     *
     * This method retrieves the PortCode associated with the specified
     * Ethernet identifier.
     */
    PortCode& parseEthernetXtoPortCode(uint8_t EthernetX);

    BtWorkSpace& btWorkSpace = BtWorkSpace::getInstance();              ///< Reference to the workspace instance.
    std::map<uint8_t, PortCode> allPortCode;                            ///< Mapping of Ethernet identifiers to PortCodes.
    std::map<Matrix_Num, std::map<Max_Power, uint8_t>> powerMapping;    ///< Mapping of power settings.
};
