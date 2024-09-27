#include "LogMessage.h"
#include <iomanip>

std::mutex LogMessage::log_mutex_;

LogMessage::LogMessage(LogLevel level, const std::string& file, int line)
    : level_(level), file_(extractFileName(file)), line_(line) {
}

void LogMessage::outputLog() {
    std::lock_guard<std::mutex> lock(log_mutex_);

    std::time_t t = std::time(nullptr);
    std::tm* local_time = std::localtime(&t);
    std::cerr << "[" << std::put_time(local_time, "%Y-%m-%d %H:%M:%S") << "] ";
    std::cerr << "[" << getLogLevelName() << "] ";
#ifndef NDEBUG
    std::cerr << file_ << ":" << line_ << " ";
#endif
    std::cerr << stream_.str() << std::endl;

    if (level_ == LogLevel::FATAL) {
        std::abort();
    }
}

LogMessage::~LogMessage() {
#ifndef NDEBUG
    outputLog();
#else
    if (level_ != LogLevel::DEBUG)
        outputLog();
#endif
}

std::string LogMessage::getLogLevelName() const {
    switch (level_) {
    case LogLevel::DEBUG:   return "DEBUG";
    case LogLevel::INFO:    return "INFO";
    case LogLevel::WARNING: return "WARNING";
    case LogLevel::ERROR:   return "ERROR";
    case LogLevel::FATAL:   return "FATAL";
    default:                return "UNKNOWN";
    }
}

std::string LogMessage::extractFileName(const std::string& filePath) const {
    auto pos = filePath.find_last_of('/');
    return (pos != std::string::npos) ? filePath.substr(pos + 1) : filePath;
}