#pragma once
#include "Utils.h"
/**
 * @class StructFormatter
 * @brief A class for parsing and formatting various structures related to POE (Power over Ethernet) messages.
 *
 * This class provides static methods to parse input messages, convert data to string representations, and
 * extract relevant information from raw data. It is designed to work with the InputMessage and OutputMessage
 * structures, as well as to facilitate data conversion and interpretation of port statuses.
 */
class StructFormatter {
public:
    /**
     * @brief Parses an InputMessage and returns a vector of uint8_t.
     * @param input The InputMessage to be parsed.
     * @return A vector of uint8_t representing the parsed input data.
     */
    static std::vector<uint8_t> parseInput(const InputMessage& input);

    /**
     * @brief Converts a vector of uint8_t to a vector of string representations.
     * @param tempArgs The vector of uint8_t to be converted.
     * @return A vector of strings representing the hexadecimal values of the input bytes.
     */
    static std::vector<std::string> toString(const std::vector<uint8_t>& tempArgs);

    /**
     * @brief Parses a shell string to create an OutputMessage.
     * @param shellString The input string containing the shell data.
     * @return An OutputMessage object populated with parsed data.
     */
    static OutputMessage parseString(const std::string& shellString);

    /**
     * @brief Parses a PortCode and returns a PortInfo structure.
     * @param portCode The PortCode to be parsed.
     * @return A PortInfo object containing parsed information.
     */
    static PortInfo parsePortCode(const PortCode& portCode);

    /**
     * @brief Parses hex data from a specific section of input.
     * @param number The number of bytes to parse.
     * @param input The input string to parse.
     * @param sectionName The name of the section to search for.
     * @return A vector of uint8_t containing the parsed hex data.
     */
    static std::vector<uint8_t> parseHexDataFromSection(const uint8_t number, const std::string& input, const std::string& sectionName);

    /**
     * @brief Parses the interface address to a string representation.
     * @param interfaceAddr The interface address to be parsed.
     * @return A string representing the parsed interface.
     */
    static std::string parseInterface(uint8_t interfaceAddr);

    /**
     * @brief Parses the POE status from a port status byte.
     * @param portStatus The port status byte to be parsed.
     * @return The corresponding Poe_Status enumeration value.
     */
    static Poe_Status parsePoeStatus(uint8_t portStatus);

    /**
     * @brief Parses the matrix number from a port status byte.
     * @param portStatus The port status byte to be parsed.
     * @return The corresponding Matrix_Num enumeration value.
     */
    static Matrix_Num parseMatrix(uint8_t portStatus);

    /**
     * @brief Converts milliamps to amps.
     * @param current_mA The current in milliamps.
     * @return The current in amps.
     */
    static double convertToAmps(uint16_t current_mA);

    /**
     * @brief Converts tenths of volts to volts.
     * @param voltage_0_1V The voltage in tenths of volts.
     * @return The voltage in volts.
     */
    static double convertToVolts(uint16_t voltage_0_1V);

    /**
     * @brief Converts tenths of watts to watts.
     * @param wattage_0_1V The wattage in tenths of watts.
     * @return The wattage in watts.
     */
    static double convertToWatts(uint16_t wattage_0_1V);

    /**
     * @brief Parses the maximum power based on matrix number and port operation mode.
     * @param matrix_Num The matrix number.
     * @param portOperationMode The port operation mode.
     * @return The corresponding Max_Power enumeration value.
     */
    static Max_Power parseMaxPower(Matrix_Num matrix_Num, uint8_t portOperationMode);

    /**
     * @brief Calculates power based on the maximum power setting.
     * @param power The power to be calculated.
     * @param maxPower The maximum power setting.
     * @return The calculated power based on the maximum power.
     */
    static double calculatePower_MaxPower(double power, Max_Power maxPower);

    /**
     * @brief Calculates power based on device PSU ratings.
     * @param power The power to be calculated.
     * @return The calculated power for the device's PSU.
     */
    static double calculatePower_DevicePSU(double power);

    /**
     * @brief Parses the legacy detection status from the port operation mode.
     * @param portOperationMode The port operation mode to be parsed.
     * @return The corresponding Legacy_Detect enumeration value.
     */
    static Legacy_Detect parseLegacyDetect(uint8_t portOperationMode);

    /**
     * @brief Parses the port priority from a byte.
     * @param portPriority The port priority byte to be parsed.
     * @return The corresponding Port_Priority enumeration value.
     */
    static Port_Priority parsePortPriority(uint8_t portPriority);

    /**
     * @brief Converts Poe_Status to its string representation.
     *
     * @param status The Poe_Status value to convert.
     * @return A string representing the Poe_Status.
     */
    static std::string toString(Poe_Status status);

    /**
     * @brief Converts Max_Power to its string representation.
     *
     * @param power The Max_Power value to convert.
     * @return A string representing the Max_Power.
     */
    static std::string toString(Max_Power power);

    /**
     * @brief Converts Legacy_Detect to its string representation.
     *
     * @param detect The Legacy_Detect value to convert.
     * @return A string representing the Legacy_Detect.
     */
    static std::string toString(Legacy_Detect detect);

    /**
     * @brief Converts Matrix_Num to its string representation.
     *
     * @param matrix The Matrix_Num value to convert.
     * @return A string representing the Matrix_Num.
     */
    static std::string toString(Matrix_Num matrix);

    /**
     * @brief Converts Port_Priority to its string representation.
     *
     * @param matrix The Port_Priority value to convert.
     * @return A string representing the Port_Priority.
     */
    static std::string toString(Port_Priority port_Priority);
    /**
     * @brief Converts a string representation of EthernetX to its integer equivalent.
     *
     * @param EthernetX The string representation of EthernetX.
     * @return The corresponding uint8_t integer value.
     * @throws std::runtime_error if the string does not contain a valid number.
     */
    static uint8_t toInt(const std::string& EthernetX);

private:
    /**
     * @brief Populates an OutputMessage with parsed send and read data.
     * @param message The OutputMessage to be populated.
     * @param sendData The vector of uint8_t for send data.
     * @param readData The vector of uint8_t for read data.
     * @param pmsgCode The parsed message code.
     */
    static void populateOutputMessage(OutputMessage& message, const std::vector<uint8_t>& sendData, const std::vector<uint8_t>& readData, uint8_t pmsgCode);
};
