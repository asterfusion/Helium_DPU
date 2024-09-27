#pragma once
#include <iostream>
#include <sstream>
#include <ctime>
#include <cstdint>
#include <string>
#include <mutex>

/**
 * @brief Enum representing the logging levels.
 */
enum LogLevel { DEBUG, INFO, WARNING, ERROR, FATAL };

/**
 * @brief Class for creating log messages.
 *
 * The LogMessage class captures log messages with a specific log level,
 * file name, and line number. It allows streaming of different data types
 * into the log message and handles thread-safe output.
 */
class LogMessage {
public:
    /**
     * @brief Constructs a LogMessage instance.
     *
     * @param level The logging level.
     * @param file The source file name.
     * @param line The line number in the source file.
     */
    LogMessage(LogLevel level, const std::string& file, int line);

    /**
     * @brief Stream operator to append messages to the log.
     *
     * @tparam T The type of the message to be appended.
     * @param msg The message to append.
     * @return A reference to this LogMessage instance.
     */
    template<typename T>
    LogMessage& operator<<(const T& msg) {
        stream_ << msg;
        return *this;
    }

    /**
     * @brief Stream operator overload for uint8_t.
     *
     * @param msg The uint8_t message to append.
     * @return A reference to this LogMessage instance.
     */
    LogMessage& operator<<(const uint8_t& msg) {
        stream_ << static_cast<int>(msg);
        return *this;
    }

    /**
     * @brief Outputs the log message to the console.
     */
    void outputLog();

    /**
     * @brief Destructor for LogMessage.
     *
     * Outputs the log message when the instance goes out of scope,
     * depending on the log level and debug mode.
     */
    ~LogMessage();

private:
    /**
     * @brief Retrieves the string representation of the log level.
     *
     * @return The log level as a string.
     */
    std::string getLogLevelName() const;

    /**
     * @brief Extracts the file name from the full file path.
     *
     * @param filePath The full path of the file.
     * @return The extracted file name.
     */
    std::string extractFileName(const std::string& filePath) const;

    LogLevel level_;                ///< The logging level of the message.
    std::string file_;              ///< The source file name.
    int line_;                      ///< The line number in the source file.
    std::ostringstream stream_;     ///< The stream to construct the log message.
    static std::mutex log_mutex_;   ///< Mutex for thread-safe logging.
};

// Macro to create a log message with the current file and line.
#define LOG(level) LogMessage(level, __FILE__, __LINE__)
